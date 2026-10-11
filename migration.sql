-- v1 se v2 upgrade: Supabase SQL Editor me ek baar run karo
create table if not exists units(id uuid primary key default gen_random_uuid(), subject_id uuid references subjects(id) on delete cascade, name text not null, created_at timestamptz default now());
alter table units enable row level security;
alter table uploads add column if not exists unit_id uuid references units(id) on delete cascade;
