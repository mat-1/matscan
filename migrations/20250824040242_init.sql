create table
    favicons (
        hash bytea primary key,
        data text not null,
        first_seen timestamp without time zone not null default now ()
    );

create table
    servers (
        -- we store the ipv4 as a signed 32-bit integer
        ip integer not null,
        port smallint not null,
        first_pinged timestamp without time zone not null default now (),
        last_pinged timestamp without time zone not null,
        last_time_player_online timestamp without time zone,
        last_time_no_players_online timestamp without time zone,
        is_online_mode boolean,
        favicon_hash bytea references favicons (hash),
        -- field not present for servers migrated from the old matscan
        description_json text,
        description_plaintext text not null,
        online_players integer,
        max_players integer,
        version_name text,
        version_protocol integer,
        enforces_secure_chat boolean,
        previews_chat boolean,
        fingerprint_field_order text,
        fingerprint_is_incorrect_field_order boolean not null default false,
        fingerprint_is_empty_sample boolean not null default false,
        fingerprint_is_empty_favicon boolean not null default false,
        -- non vanilla fields
        -- nochatreports and similar mods
        prevents_chat_reports boolean,
        -- forge
        forgedata_fml_network_version integer,
        -- old forge servers
        modinfo_type text,
        -- neoforged
        is_modded boolean,
        -- bettercompatibilitychecker
        modpackdata_project_id integer,
        modpackdata_name text,
        modpackdata_version text,
        primary key (ip, port)
    );

create index last_pinged_index on servers (last_pinged);

create table
    server_players (
        server_ip integer not null,
        server_port smallint not null,
        uuid uuid not null,
        username text not null,
        online_mode boolean,
        first_seen timestamp without time zone not null default now (),
        last_seen timestamp without time zone not null,
        primary key (server_ip, server_port, uuid),
        foreign key (server_ip, server_port) references servers (ip, port) on delete cascade
    );

-- these ips have the same server on every port
create table
    ips_with_aliased_servers (
        ip integer primary key,
        -- usually 25565
        allowed_port smallint not null,
        first_seen timestamp without time zone not null default now (),
        last_checked timestamp without time zone not null default now ()
    );