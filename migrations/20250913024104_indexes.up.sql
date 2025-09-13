alter index last_pinged_index rename to last_pinged_idx;

-- C collation results in faster comparisons
alter table servers alter column description_json set data type text collate "C";
alter table servers alter column description_plaintext set data type text collate "C";
alter table servers alter column version_name set data type text collate "C";
alter table servers alter column fingerprint_field_order set data type text collate "C";
alter table servers alter column modinfo_type set data type text collate "C";
alter table servers alter column modpackdata_name set data type text collate "C";
alter table servers alter column modpackdata_version set data type text collate "C";

alter table server_players alter column username set data type text collate "C";

create index ip_port_idx on servers (ip, port);
create index port_idx on servers (port);
create index first_pinged_idx on servers (first_pinged);
create index last_time_player_online_idx on servers (last_time_player_online);
create index last_time_no_players_online_idx on servers (last_time_no_players_online);
create index favicon_hash_idx on servers (favicon_hash);
create index online_players_idx on servers (online_players);
create index max_players_idx on servers (max_players);
create index version_protocol_idx on servers (version_protocol);
create index fingerprint_field_order_idx on servers (fingerprint_field_order);

create index player_server_ip_port_idx on server_players (server_ip, server_port);
create index player_username_idx on server_players (username);
create index player_uuid_idx on server_players (uuid);
create index player_first_seen_idx on server_players (first_seen);
create index player_last_seen_idx on server_players (last_seen);

-- trigram indexes

create extension pg_trgm;

create index description_plaintext_trgm_idx on servers using gin (description_plaintext gin_trgm_ops);
create index version_name_trgm_idx on servers using gin (version_name gin_trgm_ops);

create index username_trgm on server_players using gin (username gin_trgm_ops);

-- faster random ordering

create extension tsm_system_rows;