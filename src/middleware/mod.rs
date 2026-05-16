use crate::errors::{GatewayError, GatewayResult};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
    pub extensions: std::collections::HashMap<String, serde_json::Value>,
    pub start_time: std::time::Instant,
}

impl RequestContext {
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            path: path.to_string(),
            headers: std::collections::HashMap::new(),
            body: Vec::new(),
            extensions: std::collections::HashMap::new(),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn set_extension(&mut self, key: &str, value: serde_json::Value) {
        self.extensions.insert(key.to_string(), value);
    }

    pub fn get_extension(&self, key: &str) -> Option<&serde_json::Value> {
        self.extensions.get(key)
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

#[derive(Debug, Clone)]
pub struct ResponseContext {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
    pub duration: std::time::Duration,
}

impl ResponseContext {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: std::collections::HashMap::new(),
            body: Vec::new(),
            duration: std::time::Duration::ZERO,
        }
    }

    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn ok() -> Self {
        Self::new(200)
    }

    pub fn not_found() -> Self {
        Self::new(404)
    }

    pub fn internal_error() -> Self {
        Self::new(500)
    }
}

pub trait Middleware: Send + Sync {
    fn name(&self) -> &str;

    fn handle(
        &self,
        ctx: RequestContext,
        next: Box<dyn FnOnce(RequestContext) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> + Send>,
    ) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>>;
}

pub struct MiddlewareChain {
    middlewares: Vec<Arc<dyn Middleware>>,
}

impl MiddlewareChain {
    pub fn new() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }

    pub fn add<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares.push(Arc::new(middleware));
        self
    }

    pub fn add_arc(mut self, middleware: Arc<dyn Middleware>) -> Self {
        self.middlewares.push(middleware);
        self
    }

    pub async fn execute(&self, ctx: RequestContext) -> GatewayResult<ResponseContext> {
        let middlewares = self.middlewares.clone();
        let chain = Arc::new(middlewares);
        execute_chain(&chain, 0, ctx).await
    }

    pub fn len(&self) -> usize {
        self.middlewares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.middlewares.is_empty()
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

async fn execute_chain(
    chain: &Arc<Vec<Arc<dyn Middleware>>>,
    index: usize,
    ctx: RequestContext,
) -> GatewayResult<ResponseContext> {
    if index >= chain.len() {
        return Ok(ResponseContext::not_found());
    }

    let middleware = &chain[index];
    let chain_clone = chain.clone();

    middleware
        .handle(ctx, Box::new(move |ctx| {
            Box::pin(async move { execute_chain(&chain_clone, index + 1, ctx).await })
        }))
        .await
}

pub struct LoggingMiddleware;

impl Middleware for LoggingMiddleware {
    fn name(&self) -> &str {
        "logging"
    }

    fn handle(
        &self,
        ctx: RequestContext,
        next: Box<dyn FnOnce(RequestContext) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> + Send>,
    ) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> {
        Box::pin(async move {
            tracing::info!(
                method = %ctx.method,
                path = %ctx.path,
                "request started"
            );

            let result = next(ctx).await;

            if let Ok(ref resp) = result {
                tracing::info!(
                    status = resp.status,
                    duration_ms = resp.duration.as_millis(),
                    "request completed"
                );
            }

            result
        })
    }
}

pub struct RequestIdMiddleware;

impl Middleware for RequestIdMiddleware {
    fn name(&self) -> &str {
        "request-id"
    }

    fn handle(
        &self,
        mut ctx: RequestContext,
        next: Box<dyn FnOnce(RequestContext) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> + Send>,
    ) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> {
        Box::pin(async move {
            let request_id = uuid::Uuid::new_v4().to_string();
            ctx.set_extension("request_id", serde_json::json!(request_id));
            ctx.headers.insert("X-Request-ID".to_string(), request_id.clone());

            tracing::Span::current().record("request_id", &request_id);

            next(ctx).await
        })
    }
}

pub struct TimeoutMiddleware {
    timeout: std::time::Duration,
}

impl TimeoutMiddleware {
    pub fn new(timeout: std::time::Duration) -> Self {
        Self { timeout }
    }
}

impl Middleware for TimeoutMiddleware {
    fn name(&self) -> &str {
        "timeout"
    }

    fn handle(
        &self,
        ctx: RequestContext,
        next: Box<dyn FnOnce(RequestContext) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> + Send>,
    ) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> {
        let timeout = self.timeout;
        Box::pin(async move {
            match tokio::time::timeout(timeout, next(ctx)).await {
                Ok(result) => result,
                Err(_) => Err(GatewayError::Timeout(
                    crate::errors::TimeoutError::RequestTimeout {
                        duration_ms: timeout.as_millis() as u64,
                    },
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMiddleware {
        name: String,
        delay: std::time::Duration,
    }

    impl Middleware for TestMiddleware {
        fn name(&self) -> &str {
            &self.name
        }

        fn handle(
            &self,
            ctx: RequestContext,
            next: Box<dyn FnOnce(RequestContext) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> + Send>,
        ) -> Pin<Box<dyn Future<Output = GatewayResult<ResponseContext>> + Send>> {
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                next(ctx).await
            })
        }
    }

    #[tokio::test]
    async fn test_middleware_chain_execution() {
        let chain = MiddlewareChain::new()
            .add(TestMiddleware {
                name: "test1".to_string(),
                delay: std::time::Duration::from_millis(10),
            })
            .add(TestMiddleware {
                name: "test2".to_string(),
                delay: std::time::Duration::from_millis(10),
            });

        let ctx = RequestContext::new("GET", "/test");
        let result = chain.execute(ctx).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn test_timeout_middleware() {
        let chain = MiddlewareChain::new().add(TimeoutMiddleware::new(std::time::Duration::from_millis(50)));

        let ctx = RequestContext::new("GET", "/test");
        let result = chain.execute(ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GatewayError::Timeout(_)));
    }

    #[test]
    fn test_request_context_extensions() {
        let mut ctx = RequestContext::new("GET", "/test");
        ctx.set_extension("key", serde_json::json!("value"));
        assert_eq!(ctx.get_extension("key").unwrap().as_str().unwrap(), "value");
    }

    #[test]
    fn test_response_context_helpers() {
        assert_eq!(ResponseContext::ok().status, 200);
        assert_eq!(ResponseContext::not_found().status, 404);
        assert_eq!(ResponseContext::internal_error().status, 500);
    }

    #[test]
    fn test_middleware_chain_length() {
        let chain = MiddlewareChain::new()
            .add(TestMiddleware {
                name: "test".to_string(),
                delay: std::time::Duration::ZERO,
            });
        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
    }
}
