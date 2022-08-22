CREATE TABLE measurements (
  workload_id TEXT UNIQUE NOT NULL,
  launch_measurement TEXT NOT NULL
);
CREATE TABLE configs (
  workload_id TEXT UNIQUE NOT NULL,
  tee_config TEXT NOT NULL
);
CREATE TABLE secrets (
  key_id TEXT UNIQUE NOT NULL,
  secret TEXT NOT NULL
);
