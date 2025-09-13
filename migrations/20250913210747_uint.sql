-- migrate to unsigned integers to simplify some logic (especially when comparing ips/ports in the database)

-- requires pg-uint128 to be installed, see https://github.com/pg-uint/pg-uint128

create extension uint128;

alter table server_players drop constraint server_players_server_ip_server_port_fkey;
alter table servers drop constraint servers_pkey;

alter table servers alter column ip set data type uint4 using ((ip::bigint + 4294967296::bigint) % 4294967296::bigint)::uint4;
alter table servers alter column port set data type uint2 using ((port::bigint + 65536::bigint) % 65536::bigint)::uint2;
alter table server_players alter column server_ip set data type uint4 using ((server_ip::bigint + 4294967296::bigint) % 4294967296::bigint)::uint4;
alter table server_players alter column server_port set data type uint2 using ((server_port::bigint + 65536::bigint) % 65536::bigint)::uint2;
alter table ips_with_aliased_servers alter column ip set data type uint4 using ((ip::bigint + 4294967296::bigint) % 4294967296::bigint)::uint4;

alter table servers add primary key (ip, port);
alter table server_players
    add constraint server_players_server_ip_server_port_fkey
    foreign key (server_ip, server_port)
    references servers (ip, port)
    on delete cascade;
