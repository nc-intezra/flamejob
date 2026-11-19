CREATE TABLE device_samples (
  id         bigserial PRIMARY KEY,
  ts         timestamptz NOT NULL DEFAULT now(),
  name       text NOT NULL,
  kind       text NOT NULL,          -- 'gpu' | 'cpu'
  temp       integer,
  util       integer,
  mem_used   bigint,                 -- MiB
  mem_total  bigint,
  pstate     text,
  power_w    integer,
  fan        integer,
  hashrate   bigint
);
CREATE INDEX ix_device_samples_ts ON device_samples(ts DESC);
