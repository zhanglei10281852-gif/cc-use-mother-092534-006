"""SQLite 持久化层。

只负责 schema、连接与行映射；所有业务规则在 :mod:`tracechain.service`。
数据库文件可直接复制归档，重启后由服务执行恢复校验。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_VERSION = "1"

SCHEMA = """
create table if not exists meta(
  key text primary key,
  value text not null
);

create table if not exists task_families(
  tenant_id text not null,
  family_id text not null,
  root_task_id text not null,
  title text,
  status text not null default 'open',
  created_at text not null,
  created_by text not null,
  frozen_at text,
  frozen_by text,
  released_at text,
  released_by text,
  primary key (tenant_id, family_id)
);

create table if not exists delegations(
  tenant_id text not null,
  delegation_id text not null primary key,
  family_id text not null,
  parent_task_id text not null,
  child_task_id text not null,
  instruction_hash text not null,
  instruction_text text,
  correlation_key text not null,
  expected_total integer,
  status text not null default 'collecting',
  head_hash text,
  sealed_at text,
  sealed_by text,
  seal_root_hash text,
  sealed_head_hash text,
  created_event_seq integer not null,
  created_at text not null,
  created_by text not null,
  unique(tenant_id, family_id, correlation_key),
  foreign key (tenant_id, family_id) references task_families(tenant_id, family_id)
);

create table if not exists fragments(
  tenant_id text not null,
  fragment_id text not null primary key,
  delegation_id text not null,
  source_id text not null,
  source_seq integer not null check (source_seq >= 1),
  content_text text not null,
  content_hash text not null,
  labels_text text,
  status text not null,
  confirmations integer not null default 1,
  received_at text not null,
  unique(tenant_id, delegation_id, source_seq, content_hash)
);
create index if not exists idx_fragments_delegation on fragments(delegation_id, source_seq);

create table if not exists chain_entries(
  delegation_id text not null,
  received_order integer not null check (received_order >= 1),
  fragment_id text not null,
  entry_kind text not null,
  fork_id text,
  prev_hash text not null,
  entry_hash text not null,
  appended_at text not null,
  primary key (delegation_id, received_order)
);

create table if not exists gaps(
  tenant_id text not null,
  delegation_id text not null,
  missing_seq integer not null check (missing_seq >= 1),
  status text not null default 'open',
  detected_event_seq integer,
  detected_at text not null,
  filled_fragment_id text,
  filled_at text,
  primary key (delegation_id, missing_seq)
);

create table if not exists fork_cases(
  tenant_id text not null,
  fork_id text not null primary key,
  delegation_id text not null,
  source_seq integer not null,
  source_id text not null,
  status text not null,
  candidate_ids text not null,
  opened_event_seq integer not null,
  opened_at text not null,
  opened_by text not null,
  claimed_by text,
  resolution_action text,
  resolution_fragment_id text,
  resolution_history text not null default '[]',
  resolved_by text,
  resolved_at text,
  rationale text
);
-- 同一委派同一序列号至多一个活跃分叉案件（裁决后允许保留多条历史）。
create unique index if not exists idx_active_fork
  on fork_cases(delegation_id, source_seq)
  where status in ('open', 'adjudicating');

create table if not exists events(
  event_seq integer primary key autoincrement,
  event_id text not null unique,
  tenant_id text not null,
  event_type text not null,
  aggregate_kind text not null,
  aggregate_id text not null,
  occurred_at text not null,
  actor_id text not null,
  payload_text text not null,
  payload_hash text not null,
  prev_hash text not null,
  entry_hash text not null
);
create index if not exists idx_events_aggregate on events(tenant_id, aggregate_kind, aggregate_id, event_seq);

create table if not exists read_audit(
  audit_id text not null primary key,
  tenant_id text not null,
  reader_id text not null,
  reader_role text not null,
  access_kind text not null,
  family_id text,
  delegation_id text,
  fragment_id text,
  export_id text,
  raw_content_hash text,
  projection_hash text,
  result_count integer,
  recorded_event_seq integer not null,
  read_at text not null
);
create index if not exists idx_audit_family on read_audit(tenant_id, family_id, read_at);
create index if not exists idx_audit_reader on read_audit(tenant_id, reader_id, read_at);

create table if not exists exports(
  tenant_id text not null,
  export_id text not null primary key,
  family_id text not null,
  scope_text text not null,
  manifest_text text not null,
  export_digest text not null,
  created_by text not null,
  created_role text not null,
  created_event_seq integer not null,
  created_at text not null
);
"""


class TraceStore:
    """打开并维护一个追踪证据数据库。"""

    def __init__(self, path: str | Path | None = None):
        self.path = ":memory:" if path is None else str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("pragma foreign_keys = on")
        if self.path != ":memory:":
            # WAL 保证写入持久化后再返回；重启恢复只依赖已 fsync 的提交。
            self.conn.execute("pragma journal_mode = wal")
            self.conn.execute("pragma synchronous = full")
        self.conn.executescript(SCHEMA)
        self.conn.execute(
            "insert or ignore into meta(key, value) values ('schema_version', ?)",
            (SCHEMA_VERSION,),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "TraceStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
