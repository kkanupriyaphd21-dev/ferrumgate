use crate::zone::TcpZoneMetrics;

#[derive(Clone, Debug)]
pub struct ZoneMetricsSensor {
    pub metrics: TcpZoneMetrics,
}

pub type ZoneSensorIo<T> = kkanupriyaphd21-dev_io::SensorIo<T, ZoneMetricsSensor>;

impl kkanupriyaphd21-dev_io::Sensor for ZoneMetricsSensor {
    fn record_read(&mut self, sz: usize) {
        self.metrics.recv_bytes.inc_by(sz as u64);
    }

    fn record_write(&mut self, sz: usize) {
        self.metrics.send_bytes.inc_by(sz as u64);
    }

    fn record_close(&mut self, _eos: Option<kkanupriyaphd21-dev_errno::Errno>) {}

    fn record_error<T>(&mut self, op: kkanupriyaphd21-dev_io::Poll<T>) -> kkanupriyaphd21-dev_io::Poll<T> {
        op
    }
}
