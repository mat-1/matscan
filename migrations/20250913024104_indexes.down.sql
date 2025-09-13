alter index last_pinged_idx rename to last_pinged_index;

drop index ip_port_idx;
drop index port_idx;
drop index first_pinged_idx;
drop index last_time_player_online_idx;
drop index last_time_no_players_online_idx;
drop index favicon_hash_idx;
drop index online_players_idx;
drop index max_players_idx;
drop index version_protocol_idx;
drop index fingerprint_field_order_idx;

drop index player_server_ip_port_idx;
drop index player_username_idx;
drop index player_uuid_idx;
drop index player_first_seen_idx;
drop index player_last_seen_idx;

-- trigram indexes

drop index description_plaintext_trgm_idx;
drop index version_name_trgm_idx;

drop index username_trgm;

drop extension pg_trgm;
drop extension tsm_system_rows;
