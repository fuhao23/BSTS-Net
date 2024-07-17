@load base/protocols/dns
@load base/packet-protocols/udp
@load base/protocols/ldap


# This script is for zeek 7.0.

module feature_extract;

export{
    redef udp_content_deliver_all_orig = T;
    redef udp_content_deliver_all_resp = T;
    redef enum Log::ID += { LOG };
    redef LogAscii::use_json = T;

    type PacketInfo:record{
        is_orig:bool;
        applayerlength:count;
        timestamp:time;
        appinfo:string &optional; 
    };

    type TrafficInfo:record{
        srcip:addr &optional; 
        srcport:port &optional;
        dstip:addr &optional;
        dstport:port &optional;
        packets: vector of PacketInfo &optional;
    };


    type Logs:record{
        uid: string &log;
        srcip:addr &optional &log; 
        srcport:port &optional &log;
        dstip:addr &optional &log;
        dstport:port &optional &log;
        is_orig:bool &log;
        applayerlength:count &log;
        timestamp:time &log;
        appinfo:string &optional &log; 
    };


    global traffic_infos:table[string] of TrafficInfo;


    function compareByTs(pkt_a:PacketInfo,pkt_b:PacketInfo):int 
    {
        local time_compare=pkt_a$timestamp<pkt_b$timestamp;
        return -1*|time_compare|;
    }
}

event udp_contents(u: connection, is_orig: bool, contents: string) {
    local packet_flow_id=u$uid;
    local packet_id=u$id;
    local srcip:addr=packet_id$orig_h;
    local srcport:port=packet_id$orig_p;
    local dstip:addr=packet_id$resp_h;
    local dstport:port=packet_id$resp_p;


    local packet_info=PacketInfo(
        $is_orig=is_orig,
        $applayerlength=|contents|,
        $timestamp=network_time()
    );

    if(packet_flow_id !in traffic_infos){
        traffic_infos[packet_flow_id]=TrafficInfo(
            $srcip=srcip,
            $srcport=srcport,
            $dstip=dstip,
            $dstport=dstport
        );
        traffic_infos[packet_flow_id]$packets=vector();
    };

    traffic_infos[packet_flow_id]$packets+=packet_info;
}


event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
    local packet_flow_id=c$uid;
    local packet_id=c$id;
    local srcip:addr=packet_id$orig_h;
    local srcport:port=packet_id$orig_p;
    local dstip:addr=packet_id$resp_h;
    local dstport:port=packet_id$resp_p;


    local packet_info=PacketInfo(
        $is_orig=is_orig,
        $applayerlength=len,
        $timestamp=network_time()
    );

    if(packet_flow_id !in traffic_infos){
        traffic_infos[packet_flow_id]=TrafficInfo(
            $srcip=srcip,
            $srcport=srcport,
            $dstip=dstip,
            $dstport=dstport
        );
        traffic_infos[packet_flow_id]$packets=vector();
    };

    traffic_infos[packet_flow_id]$packets+=packet_info;
}


event SSH::log_ssh(rec: SSH::Info) {
    local flow_uid=rec$uid;
    local ts=network_time();
    local auth_success="";
    local host_key="";
    if(rec?$auth_success)
        auth_success=cat(rec$auth_success);

    if(rec?$host_key)
        host_key=cat(rec$host_key);

        
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<ssh_login>]";
                packet$appinfo+="authsuccess("+cat(auth_success)+");";
                packet$appinfo+="hostkey("+host_key+");";
            }else{
                packet$appinfo="[<ssh_login>]";
                packet$appinfo+="authsuccess("+cat(auth_success)+");";
                packet$appinfo+="hostkey("+host_key+");";
            }
            
        }
    }
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    local flow_uid=c$uid;
    local ts=network_time();

    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<http>]";
                packet$appinfo+="http_request_method("+cat(method)+");";
                packet$appinfo+="http_request_url("+cat(original_URI)+");";
            }else{
                packet$appinfo="[<http>]";
                packet$appinfo+="http_request_method("+cat(method)+");";
                packet$appinfo+="http_request_url("+cat(original_URI)+");";
            }
            
        }
    }
}


event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string) {
    local flow_uid=c$uid;
    local ts=network_time();

    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<dns_request>]";
                packet$appinfo+="request_domainname("+cat(query)+");";
            }else{
                packet$appinfo="[<dns_request>]";
                packet$appinfo+="request_domainname("+cat(query)+");";
            }
            
        }
    }
}


event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    local flow_uid=c$uid;
    local ts=network_time();

    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<dns_a_reply>]";
                packet$appinfo+="reply_A_domainname("+cat(ans$query)+");";
                packet$appinfo+="reply_A_res("+cat(a)+");";
            }
            else{
                packet$appinfo="[<dns_a_reply>]";
                packet$appinfo+="reply_A_domainname("+cat(ans$query)+");";
                packet$appinfo+="reply_A_res("+cat(a)+");";
            }
         
        }
    }
}


event ssl_handshake_message(c: connection, is_client: bool, msg_type: count, length: count) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_handshake>]";
                packet$appinfo+="is_client("+cat(is_client)+");";
                packet$appinfo+="msg_type("+cat(msg_type)+");";
            }else{
                packet$appinfo="[<tls_handshake>]";
                packet$appinfo+="is_client("+cat(is_client)+");";
                packet$appinfo+="msg_type("+cat(msg_type)+");";
            }

        }
    }
}

event ssl_alert(c: connection, is_client: bool, level: count, desc: count) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_alert>]";
            }else{
                packet$appinfo="[<tls_alert>]";
            }
        }
    }
}

event ssl_certificate_request(c: connection, is_client: bool, certificate_types: index_vec, supported_signature_algorithms: signature_and_hashalgorithm_vec, certificate_authorities: string_vec) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_cer_request>]";
            }else{
                packet$appinfo="[<tls_cer_request>]";
            }
        }
    }
}

event ssl_change_cipher_spec(c: connection, is_client: bool) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_change_cipher>]";
            }else{
                packet$appinfo="[<tls_change_cipher>]";
            }
        }
    }
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_client_hello>]";
            }else{
                packet$appinfo="[<tls_client_hello>]";
            }

        }
    }
}

event ssl_encrypted_data(c: connection, is_client: bool, record_version: count, content_type: count, length: count) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_encrypted_data>]";
            }else{
                packet$appinfo="[<tls_encrypted_data>]";
            }

        }
    }
}

event ssl_established(c: connection) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_established>]";
            }else{
                packet$appinfo="[<tls_established>]";
            }

        }
    }
}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_sni>]";
                packet$appinfo+="name0("+cat(names[0])+");";
            }else{
                packet$appinfo="[<tls_sni>]";
                packet$appinfo+="name0("+cat(names[0])+");";
            }
            
        }
    }
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<tls_server_hello>]";
            }else{
                packet$appinfo="[<tls_server_hello>]";
            }

        }
    }
}

# event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate) {
#     # print f$info;
# }

event ftp_request(c: connection, command: string, arg: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<ftp_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arg)+");";
            }else{
                packet$appinfo="[<ftp_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arg)+");";
            }
            
        }
    }
}

event smtp_data(c: connection, is_orig: bool, data: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<smtp_data>]";
                packet$appinfo+="is_orig("+cat(is_orig)+");";
                packet$appinfo+="data("+cat(data)+");";
            }else{
                packet$appinfo="[<smtp_data>]";
                packet$appinfo+="is_orig("+cat(is_orig)+");";
                packet$appinfo+="data("+cat(data)+");";
            }
        }
    }
}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<smtp_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arg)+");";
            }else{
                packet$appinfo="[<smtp_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arg)+");";
            }
        }
    }
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<smtp_reply>]";
                packet$appinfo+="cmd("+cat(cmd)+");";
                packet$appinfo+="msg("+cat(msg)+");";
            }else{
                packet$appinfo="[<smtp_reply>]";
                packet$appinfo+="cmd("+cat(cmd)+");";
                packet$appinfo+="msg("+cat(msg)+");";
            }
        }
    }
}

event smtp_starttls(c: connection) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<smtp_starttls>]";
            }else{
                packet$appinfo="[<smtp_starttls>]";
            }
        }
    }
}


event pop3_starttls(c: connection) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<pop3_starttls>]";
            }else{
                packet$appinfo="[<pop3_starttls>]";
            }
        }
    }
}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<pop3_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arg)+");";
            }else{
                packet$appinfo="[<pop3_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arg)+");";
            }
        }
    }
}

event pop3_login_success(c: connection, is_orig: bool, user: string, password: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<pop3_login_success>]";
                packet$appinfo+="user("+cat(user)+");";
                packet$appinfo+="password("+cat(password)+");";
            }else{
                packet$appinfo="[<pop3_login_success>]";
                packet$appinfo+="user("+cat(user)+");";
                packet$appinfo+="password("+cat(password)+");";
            }
        }
    }
}

event pop3_login_failure(c: connection, is_orig: bool, user: string, password: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<pop3_login_failure>]";
                packet$appinfo+="user("+cat(user)+");";
                packet$appinfo+="password("+cat(password)+");";
            }else{
                packet$appinfo="[<pop3_login_failure>]";
                packet$appinfo+="user("+cat(user)+");";
                packet$appinfo+="password("+cat(password)+");";
            }
        }
    }
}

event pop3_data(c: connection, is_orig: bool, data: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<pop3_data>]";
                packet$appinfo+="data("+cat(data)+");";
            }else{
                packet$appinfo="[<pop3_data>]";
                packet$appinfo+="data("+cat(data)+");";
            }
        }
    }
}

event imap_capabilities(c: connection, capabilities: string_vec) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<imap_capabilities>]";
            }else{
                packet$appinfo="[<imap_capabilities>]";
            }
        }
    }
}

event imap_starttls(c: connection) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<imap_starttls>]";
            }else{
                packet$appinfo="[<imap_starttls>]";
            }
        }
    }
}


event mysql_command_request(c: connection, command: count, arg: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mysql_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arg)+");";
            }else{
                packet$appinfo="[<mysql_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arg)+");";
            }
        }
    }
}

event mysql_ok(c: connection, affected_rows: count) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mysql_replyok>]";
                packet$appinfo+="affected_row_num("+cat(affected_rows)+");";
            }else{
                packet$appinfo="[<mysql_replyok>]";
                packet$appinfo+="affected_row_num("+cat(affected_rows)+");";
            }
        }
    }
}

event mysql_error(c: connection, code: count, msg: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mysql_rreplyerror>]";
                packet$appinfo+="code("+cat(code)+");";
                packet$appinfo+="msg("+cat(msg)+");";
            }else{
                packet$appinfo="[<mysql_rreplyerror>]";
                packet$appinfo+="code("+cat(code)+");";
                packet$appinfo+="msg("+cat(msg)+");";
            }
        }
    }
}

event mysql_result_row(c: connection, row: string_vec) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mysql_replyres>]";
                packet$appinfo+="affected_row0("+cat(row[0])+");";
            }else{
                packet$appinfo="[<mysql_replyres>]";
                packet$appinfo+="affected_row0("+cat(row[0])+");";
            }
        }
    }
}

event mysql_server_version(c: connection, ver: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mysql_server_ver>]";
                packet$appinfo+="ver("+cat(ver)+");";
            }else{
                packet$appinfo="[<mysql_server_ver>]";
                packet$appinfo+="ver("+cat(ver)+");";
            }
        }
    }
}

event mysql_handshake(c: connection, username: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mysql_handshake>]";
                packet$appinfo+="username("+cat(username)+");";
            }else{
                packet$appinfo="[<mysql_handshake>]";
                packet$appinfo+="username("+cat(username)+");";
            }
        }
    }
}


event bittorrent_peer_handshake(c: connection, is_orig: bool, reserved: string, info_hash: string, peer_id: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<bt_handshake>]";
                packet$appinfo+="peerid("+cat(peer_id)+");";
            }else{
                packet$appinfo="[<bt_handshake>]";
                packet$appinfo+="peerid("+cat(peer_id)+");";
            }
        }
    }
}

event bittorrent_peer_request(c: connection, is_orig: bool, index: count, begin: count, length: count) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<bt_request>]";
                packet$appinfo+="index("+cat(index)+");";
            }else{
                packet$appinfo="[<bt_request>]";
                packet$appinfo+="index("+cat(index)+");";
            }
        }
    }
}

event bittorrent_peer_interested(c: connection, is_orig: bool) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<bt_interested]";
            }else{
                packet$appinfo="[<bt_interested]";
            }
        }
    }
}


event irc_request(c: connection, is_orig: bool, prefix: string, command: string, arguments: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<irc_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arguments)+");";
            }else{
                packet$appinfo="[<irc_request>]";
                packet$appinfo+="cmd("+cat(command)+");";
                packet$appinfo+="arg("+cat(arguments)+");";
            }
        }
    }
}

event irc_reply(c: connection, is_orig: bool, prefix: string, code: count, params: string) {
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<irc_reply>]";
                packet$appinfo+="code("+cat(code)+");";
                packet$appinfo+="params("+cat(params)+");";
            }else{
                packet$appinfo="[<irc_reply>]";
                packet$appinfo+="code("+cat(code)+");";
                packet$appinfo+="params("+cat(params)+");";
            }
        }
    }
}


event LDAP::message(c: connection, message_id: int, opcode: LDAP::ProtocolOpcode, result: LDAP::ResultCode, matched_dn: string, diagnostic_message: string, object: string, argument: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<ldap_message>]";
                packet$appinfo+="opcode("+cat(opcode)+");";
                packet$appinfo+="result("+cat(result)+");";
                packet$appinfo+="matched_dn("+cat(matched_dn)+");";
                packet$appinfo+="diagnostic_message("+cat(diagnostic_message)+");";
                packet$appinfo+="object("+cat(object)+");";
                packet$appinfo+="arg("+cat(argument)+");";
            }else{
                packet$appinfo="[<ldap_message>]";
                packet$appinfo+="opcode("+cat(opcode)+");";
                packet$appinfo+="result("+cat(result)+");";
                packet$appinfo+="matched_dn("+cat(matched_dn)+");";
                packet$appinfo+="diagnostic_message("+cat(diagnostic_message)+");";
                packet$appinfo+="object("+cat(object)+");";
                packet$appinfo+="arg("+cat(argument)+");";
            }
        }
    }
}

event LDAP::bind_request (c: connection, message_id: int, version: int, name: string, auth_type: LDAP::BindAuthType, auth_info: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<ldap_bind_request>]";
                packet$appinfo+="msg_id("+cat(message_id)+");";
                packet$appinfo+="name("+cat(name)+");";
                packet$appinfo+="auth_info("+cat(auth_info)+");";
            }else{
               packet$appinfo="[<ldap_bind_request>]";
                packet$appinfo+="msg_id("+cat(message_id)+");";
                packet$appinfo+="name("+cat(name)+");";
                packet$appinfo+="auth_info("+cat(auth_info)+");";
            }
        }
    }
}

event LDAP::search_request (c: connection, message_id: int, base_object: string, scope: LDAP::SearchScope, deref: LDAP::SearchDerefAlias, size_limit: int, time_limit: int, types_only: bool, filter: string, attributes: vector of string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<ldap_search_request>]";
                packet$appinfo+="msg_id("+cat(message_id)+");";
                packet$appinfo+="base_obj("+cat(base_object)+");";
                packet$appinfo+="filter("+cat(filter)+");";
            }else{
                packet$appinfo="[<ldap_search_request>]";
                packet$appinfo+="msg_id("+cat(message_id)+");";
                packet$appinfo+="base_obj("+cat(base_object)+");";
                packet$appinfo+="filter("+cat(filter)+");";
            }
        }
    }
}

event LDAP::search_result_entry(c: connection, message_id: int, object_name: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<ldap_search_result>]";
                packet$appinfo+="msg_id("+cat(message_id)+");";
                packet$appinfo+="object_name("+cat(object_name)+");";
            }else{
                packet$appinfo="[<ldap_search_result>]";
                packet$appinfo+="msg_id("+cat(message_id)+");";
                packet$appinfo+="object_name("+cat(object_name)+");";
            }
        }
    }
}



event rsh_request(c: connection, client_user: string, server_user: string, line: string, new_session: bool){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_request>]";
                packet$appinfo+="client_usr("+cat(client_user)+");";
                packet$appinfo+="server_usr("+cat(server_user)+");";
            }else{
                packet$appinfo="[<rsh_request>]";
                packet$appinfo+="client_usr("+cat(client_user)+");";
                packet$appinfo+="server_usr("+cat(server_user)+");";
            }
        }
    }
}

event rsh_reply (c: connection, client_user: string, server_user: string, line: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_reply>]";
                packet$appinfo+="client_usr("+cat(client_user)+");";
                packet$appinfo+="server_usr("+cat(server_user)+");";
                packet$appinfo+="line("+cat(line)+");";
            }else{
                packet$appinfo="[<rsh_reply>]";
                packet$appinfo+="client_usr("+cat(client_user)+");";
                packet$appinfo+="server_usr("+cat(server_user)+");";
                packet$appinfo+="line("+cat(line)+");";
            }
        }
    }
}

event login_failure(c: connection, user: string, client_user: string, password: string, line: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_login_fail>]";
                packet$appinfo+="client_usr("+cat(client_user)+");";
                packet$appinfo+="usr("+cat(user)+");";
                packet$appinfo+="passwd("+cat(password)+");";
                packet$appinfo+="line("+cat(line)+");";
            }else{
                packet$appinfo="[<rsh_login_fail>]";
                packet$appinfo+="client_usr("+cat(client_user)+");";
                packet$appinfo+="usr("+cat(user)+");";
                packet$appinfo+="passwd("+cat(password)+");";
                packet$appinfo+="line("+cat(line)+");";
            }
        }
    }
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_login_success>]";
                packet$appinfo+="client_usr("+cat(client_user)+");";
                packet$appinfo+="usr("+cat(user)+");";
                packet$appinfo+="passwd("+cat(password)+");";
                packet$appinfo+="line("+cat(line)+");";
            }else{
                packet$appinfo="[<rsh_login_success>]";
                packet$appinfo+="client_usr("+cat(client_user)+");";
                packet$appinfo+="usr("+cat(user)+");";
                packet$appinfo+="passwd("+cat(password)+");";
                packet$appinfo+="line("+cat(line)+");";
            }
        }
    }
}

event login_input_line (c: connection, line: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_login_input>]";
                packet$appinfo+="line("+cat(line)+");";
            }else{
                packet$appinfo="[<rsh_login_input>]";
                packet$appinfo+="line("+cat(line)+");";
            }
        }
    }
}

event login_output_line (c: connection, line: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_login_output>]";
                packet$appinfo+="line("+cat(line)+");";
            }else{
                packet$appinfo="[<rsh_login_output>]";
                packet$appinfo+="line("+cat(line)+");";
            }
        }
    }
}

event login_confused (c: connection, msg: string, line: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_login_confused>]";
                packet$appinfo+="msg("+cat(msg)+");";
                packet$appinfo+="line("+cat(line)+");";
            }else{
                packet$appinfo="[<rsh_login_confused>]";
                packet$appinfo+="msg("+cat(msg)+");";
                packet$appinfo+="line("+cat(line)+");";
            }
        }
    }
}

event login_confused_text (c: connection, line: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_login_confused_text>]";
                packet$appinfo+="line("+cat(line)+");";
            }else{
                packet$appinfo="[<rsh_login_confused_text>]";
                packet$appinfo+="line("+cat(line)+");";
            }
        }
    }
}

event login_terminal (c: connection, terminal: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_login_terminal>]";
                packet$appinfo+="terminal("+cat(terminal)+");";
            }else{
                packet$appinfo="[<rsh_login_terminal>]";
                packet$appinfo+="terminal("+cat(terminal)+");";
            }
        }
    }
}

event login_display(c: connection, display: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rsh_login_disp>]";
                packet$appinfo+="display("+cat(display)+");";
            }else{
                packet$appinfo="[<rsh_login_disp>]";
                packet$appinfo+="display("+cat(display)+");";
            }
        }
    }
}

event mqtt_connect(c: connection, msg: MQTT::ConnectMsg){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mqtt_connect>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }else{
                packet$appinfo="[<mqtt_connect>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }
        }
    }
}

event mqtt_publish (c: connection, is_orig: bool, msg_id: count, msg: MQTT::PublishMsg){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mqtt_publish>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }else{
                packet$appinfo="[<mqtt_publish>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }
        }
    }
}

event mqtt_subscribe (c: connection, msg_id: count, topics: string_vec, requested_qos: index_vec){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mqtt_subscribe>]";
                packet$appinfo+="topics("+cat(topics[0])+");";
            }else{
                packet$appinfo="[<mqtt_subscribe>]";
                packet$appinfo+="topics("+cat(topics[0])+");";
            }
        }
    }
}

event mqtt_disconnect(c:connection){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<mqtt_disconnect>]";
            }else{
                packet$appinfo="[<mqtt_disconnect>]";
            }
        }
    }
}


event netbios_session_message (c: connection, is_orig: bool, msg_type: count, data_len: count){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<netbios_msg>]";
                packet$appinfo+="msg_type("+cat(msg_type)+");";
            }else{
                packet$appinfo="[<netbios_msg>]";
                packet$appinfo+="msg_type("+cat(msg_type)+");";
            }
        }
    }
}

event netbios_session_request (c: connection, msg: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<netbios_request>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }else{
                packet$appinfo="[<netbios_request>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }
        }
    }
}

event netbios_session_accepted(c: connection, msg: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<netbios_accept>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }else{
                packet$appinfo="[<netbios_accept>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }
        }
    }
}

event ntp_message(c: connection, is_orig: bool, msg: NTP::Message){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<ntp_msg>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }else{
                packet$appinfo="[<ntp_msg>]";
                packet$appinfo+="msg("+cat(msg)+");";
            }
        }
    }
}


event QUIC::handshake_packet (c: connection, is_orig: bool, version: count, dcid: string, scid: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<quic_handshake>]";
                packet$appinfo+="dcid("+cat(dcid)+");";
                packet$appinfo+="scid("+cat(scid)+");";
            }else{
                packet$appinfo="[<quic_handshake>]";
                packet$appinfo+="dcid("+cat(dcid)+");";
                packet$appinfo+="scid("+cat(scid)+");";
            }
        }
    }
}

event QUIC::zero_rtt_packet (c: connection, is_orig: bool, version: count, dcid: string, scid: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<quic_0rttpkt>]";
                packet$appinfo+="dcid("+cat(dcid)+");";
                packet$appinfo+="scid("+cat(scid)+");";
            }else{
                packet$appinfo="[<quic_0rttpkt>]";
                packet$appinfo+="dcid("+cat(dcid)+");";
                packet$appinfo+="scid("+cat(scid)+");";
            }
        }
    }
}


event radius_message(c: connection, result: RADIUS::Message){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<radius_msg>]";
                packet$appinfo+="result("+cat(result)+");";
            }else{
                packet$appinfo="[<radius_msg>]";
                packet$appinfo+="result("+cat(result)+");";
            }
        }
    }
}

event radius_attribute(c: connection, attr_type: count, value: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<radius_attr>]";
                packet$appinfo+="attr_type("+cat(attr_type)+");";
                packet$appinfo+="value("+cat(value)+");";
            }else{
                packet$appinfo="[<radius_attr>]";
                packet$appinfo+="value("+cat(value)+");";
            }
        }
    }
}


event rdpeudp_syn (c: connection){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rdp_udp_syn]";
            }else{
                packet$appinfo="[<rdp_udp_syn]";
            }
        }
    }
}

event rdpeudp_synack (c: connection){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<rdp_udp_synack]";
            }else{
                packet$appinfo="[<rdp_udp_synack]";
            }
        }
    }
}

event rdpeudp_data(c: connection, is_orig: bool, version: count, data: string){
    local flow_uid=c$uid;
    local ts=network_time();
    for(index,packet in traffic_infos[flow_uid]$packets){
        if(packet$timestamp==ts){
            if(packet?$appinfo){
                packet$appinfo+="[<radius_udp_data>]";
                packet$appinfo+="version("+cat(version)+");";
                packet$appinfo+="data("+cat(data)+");";
            }else{
                packet$appinfo="[<radius_udp_data>]";
                packet$appinfo+="version("+cat(version)+");";
                packet$appinfo+="data("+cat(data)+");";
            }
        }
    }
}


event zeek_init(){
    Log::create_stream(LOG, [$columns=Logs, $path="Features"]);
}



event zeek_done() {
    print "Sort by timestamp...";
    for(flow in traffic_infos){
        if(|traffic_infos[flow]$packets|<2){
            next;
        }
        traffic_infos[flow]$packets=sort(traffic_infos[flow]$packets,compareByTs);
    }
    print "Exporting log files...";
    for(flow in traffic_infos){
        local f_flow=traffic_infos[flow];
        local srcip=f_flow$srcip;
        local srcport=f_flow$srcport;
        local dstip=f_flow$dstip;
        local dstport=f_flow$dstport;

        for (packet in f_flow$packets){
            local f_packet=f_flow$packets[packet];
            local f_isorig=f_packet$is_orig;
            local f_applen=f_packet$applayerlength;
            local f_ts=f_packet$timestamp;
            if(f_packet?$appinfo){
                local f_appinfo=f_packet$appinfo;
                Log::write(feature_extract::LOG,[$uid=flow ,$srcip=srcip,$srcport=srcport,$dstip=dstip,$dstport=dstport,$is_orig=f_isorig,$applayerlength=f_applen,$timestamp=f_ts,$appinfo=f_appinfo]);

            }
            else{
                Log::write(feature_extract::LOG,[$uid=flow,$srcip=srcip,$srcport=srcport,$dstip=dstip,$dstport=dstport,$is_orig=f_isorig,$applayerlength=f_applen,$timestamp=f_ts]);
            }
        }
    }
}

