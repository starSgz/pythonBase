import time

import requests
import json

def verify_token(func):
    def wrapper(self, *args, **kwargs):
        headers = {
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "X-Cookie": "token=b53874580315cf16e7a4bfca930dbb0ff4e0b5d85c0e1cd3",
        "sec-ch-ua": "\"Google Chrome\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\"",
        }
        url = "https://{}:{}/scans".format(self.ip,self.port)
        params = {
            "folder_id": "3",
            "last_modification_date": "{}".format(int(time.time()))
        }
        response = requests.get(url, headers=headers, params=params, verify=False)
        if response.status_code==200:
            func(self, *args, **kwargs)
        else:
            # print(self.token)
            self.token = self.getNessusToken()
            func(self, *args, **kwargs)
    return wrapper

class optNessus():
    def __init__(self,ip,port):
        self.ip=ip
        self.port=port
        # self.token=self.getNessusToken()
        self.token='30a67d94f9d0540e84ff7c1821328204b3e59e6d8ef36d46sss'
        self.headers = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "X-Cookie": "token={}".format(self.token),
            "sec-ch-ua": "\"Google Chrome\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\"",
            "sec-ch-ua-mobile": "?0",
        }

    def getNessusToken(self,username=None,password=None):
        """
        获取token
        """
        url_session = "https://{}:{}/session".format(self.ip,self.port)
        headers = {
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "sec-ch-ua": "\"Google Chrome\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\""
        }
        url = url_session
        data = {
            "username": "zhuque",
            "password": "zq!!001A"
        }
        data = json.dumps(data, separators=(',', ':'))
        response = requests.post(url, headers=headers, data=data, verify=False)
        print(json.loads(response.text)['token'])
        return  json.loads(response.text).get('token')

    @verify_token
    def getScanUuid(self,template_name="advanced"):
        """
        获取扫描任务uuid
        """

        url_templates = "https://{}:{}/editor/scan/templates".format(self.ip,self.port)
        url = url_templates
        response = requests.get(url, headers=self.headers, verify=False)
        templates = json.loads(response.text)['templates']
        for template in templates:
            if template['name'] == template_name:
                print(template['uuid'])
                return template['uuid']
        return None

    @verify_token
    def add_scan(self,uuid_,name,description,targets):
        """
        添加扫描模板
        """
        url_scan = "https://{}:{}/scans".format(self.ip,self.port)
        url = url_scan
        data = {
            "uuid": uuid_,
            "plugins": {
                "SMTP problems": {
                    "status": "enabled"
                },
                "Backdoors": {
                    "status": "enabled"
                },
                "Rocky Linux Local Security Checks": {
                    "status": "enabled"
                },
                "Ubuntu Local Security Checks": {
                    "status": "enabled"
                },
                "Gentoo Local Security Checks": {
                    "status": "enabled"
                },
                "Oracle Linux Local Security Checks": {
                    "status": "enabled"
                },
                "RPC": {
                    "status": "enabled"
                },
                "Gain a shell remotely": {
                    "status": "enabled"
                },
                "Service detection": {
                    "status": "enabled"
                },
                "DNS": {
                    "status": "enabled"
                },
                "Mandriva Local Security Checks": {
                    "status": "enabled"
                },
                "Junos Local Security Checks": {
                    "status": "enabled"
                },
                "Misc.": {
                    "status": "enabled"
                },
                "FTP": {
                    "status": "enabled"
                },
                "Slackware Local Security Checks": {
                    "status": "enabled"
                },
                "Default Unix Accounts": {
                    "status": "enabled"
                },
                "AIX Local Security Checks": {
                    "status": "enabled"
                },
                "SNMP": {
                    "status": "enabled"
                },
                "OracleVM Local Security Checks": {
                    "status": "enabled"
                },
                "CGI abuses": {
                    "status": "enabled"
                },
                "Settings": {
                    "status": "enabled"
                },
                "CISCO": {
                    "status": "enabled"
                },
                "Tenable.ot": {
                    "status": "enabled"
                },
                "Firewalls": {
                    "status": "enabled"
                },
                "Databases": {
                    "status": "enabled"
                },
                "Debian Local Security Checks": {
                    "status": "enabled"
                },
                "Fedora Local Security Checks": {
                    "status": "enabled"
                },
                "Netware": {
                    "status": "enabled"
                },
                "Huawei Local Security Checks": {
                    "status": "enabled"
                },
                "Windows : User management": {
                    "status": "enabled"
                },
                "VMware ESX Local Security Checks": {
                    "status": "enabled"
                },
                "Virtuozzo Local Security Checks": {
                    "status": "enabled"
                },
                "CentOS Local Security Checks": {
                    "status": "enabled"
                },
                "Peer-To-Peer File Sharing": {
                    "status": "enabled"
                },
                "NewStart CGSL Local Security Checks": {
                    "status": "enabled"
                },
                "General": {
                    "status": "enabled"
                },
                "Policy Compliance": {
                    "status": "enabled"
                },
                "Amazon Linux Local Security Checks": {
                    "status": "enabled"
                },
                "Solaris Local Security Checks": {
                    "status": "enabled"
                },
                "F5 Networks Local Security Checks": {
                    "status": "enabled"
                },
                "Denial of Service": {
                    "status": "enabled"
                },
                "Windows : Microsoft Bulletins": {
                    "status": "enabled"
                },
                "SuSE Local Security Checks": {
                    "status": "enabled"
                },
                "Palo Alto Local Security Checks": {
                    "status": "enabled"
                },
                "Alma Linux Local Security Checks": {
                    "status": "enabled"
                },
                "Red Hat Local Security Checks": {
                    "status": "enabled"
                },
                "PhotonOS Local Security Checks": {
                    "status": "enabled"
                },
                "HP-UX Local Security Checks": {
                    "status": "enabled"
                },
                "CGI abuses : XSS": {
                    "status": "enabled"
                },
                "FreeBSD Local Security Checks": {
                    "status": "enabled"
                },
                "Windows": {
                    "status": "enabled"
                },
                "Scientific Linux Local Security Checks": {
                    "status": "enabled"
                },
                "MacOS X Local Security Checks": {
                    "status": "enabled"
                },
                "Web Servers": {
                    "status": "enabled"
                },
                "SCADA": {
                    "status": "enabled"
                }
            },
            "credentials": {
                "add": {},
                "edit": {},
                "delete": []
            },
            "settings": {
                "patch_audit_over_telnet": "no",
                "patch_audit_over_rsh": "no",
                "patch_audit_over_rexec": "no",
                "snmp_port": "161",
                "additional_snmp_port1": "161",
                "additional_snmp_port2": "161",
                "additional_snmp_port3": "161",
                "http_login_method": "POST",
                "http_reauth_delay": "",
                "http_login_max_redir": "0",
                "http_login_invert_auth_regex": "no",
                "http_login_auth_regex_on_headers": "no",
                "http_login_auth_regex_nocase": "no",
                "never_send_win_creds_in_the_clear": "yes",
                "dont_use_ntlmv1": "yes",
                "start_remote_registry": "no",
                "enable_admin_shares": "no",
                "start_server_service": "no",
                "ssh_known_hosts": "",
                "ssh_port": "22",
                "ssh_client_banner": "OpenSSH_5.0",
                "attempt_least_privilege": "no",
                "region_dfw_pref_name": "yes",
                "region_ord_pref_name": "yes",
                "region_iad_pref_name": "yes",
                "region_lon_pref_name": "yes",
                "region_syd_pref_name": "yes",
                "region_hkg_pref_name": "yes",
                "microsoft_azure_subscriptions_ids": "",
                "aws_ui_region_type": "Rest of the World",
                "aws_us_east_1": "",
                "aws_us_east_2": "",
                "aws_us_west_1": "",
                "aws_us_west_2": "",
                "aws_ca_central_1": "",
                "aws_eu_south_1": "",
                "aws_eu_west_1": "",
                "aws_eu_west_2": "",
                "aws_eu_west_3": "",
                "aws_eu_central_1": "",
                "aws_eu_north_1": "",
                "aws_af_south_1": "",
                "aws_ap_east_1": "",
                "aws_ap_northeast_1": "",
                "aws_ap_northeast_2": "",
                "aws_ap_northeast_3": "",
                "aws_ap_southeast_1": "",
                "aws_ap_southeast_2": "",
                "aws_ap_south_1": "",
                "aws_me_south_1": "",
                "aws_sa_east_1": "",
                "aws_use_https": "yes",
                "aws_verify_ssl": "yes",
                "max_compliance_output_length_kb": "",
                "log_whole_attack": "no",
                "enable_plugin_debugging": "no",
                "debug_level": "1",
                "enable_plugin_list": "no",
                "audit_trail": "use_scanner_default",
                "include_kb": "use_scanner_default",
                "custom_find_filepath_exclusions": "",
                "custom_find_filesystem_exclusions": "",
                "custom_find_filepath_inclusions": "",
                "reduce_connections_on_congestion": "no",
                "network_receive_timeout": "5",
                "max_checks_per_host": "5",
                "max_hosts_per_scan": "5",
                "max_simult_tcp_sessions_per_host": "",
                "max_simult_tcp_sessions_per_scan": "",
                "safe_checks": "yes",
                "stop_scan_on_disconnect": "no",
                "slice_network_addresses": "no",
                "auto_accept_disclaimer": "no",
                "scan.allow_multi_target": "no",
                "allow_post_scan_editing": "yes",
                "reverse_lookup": "no",
                "log_live_hosts": "no",
                "display_unreachable_hosts": "no",
                "display_unicode_characters": "no",
                "report_verbosity": "Normal",
                "report_superseded_patches": "yes",
                "silent_dependencies": "yes",
                "oracle_database_use_detected_sids": "no",
                "scan_malware": "no",
                "samr_enumeration": "yes",
                "adsi_query": "yes",
                "wmi_query": "yes",
                "rid_brute_forcing": "no",
                "request_windows_domain_info": "no",
                "scan_webapps": "no",
                "start_cotp_tsap": "8",
                "stop_cotp_tsap": "8",
                "modbus_start_reg": "0",
                "modbus_end_reg": "16",
                "test_default_oracle_accounts": "no",
                "provided_creds_only": "yes",
                "smtp_domain": "example.com",
                "smtp_from": "nobody@example.com",
                "smtp_to": "postmaster@[AUTO_REPLACED_IP]",
                "av_grace_period": "0",
                "report_paranoia": "Normal",
                "thorough_tests": "no",
                "svc_detection_on_all_ports": "yes",
                "detect_ssl": "yes",
                "ssl_prob_ports": "All ports",
                "dtls_prob_ports": "None",
                "cert_expiry_warning_days": "60",
                "enumerate_all_ciphers": "yes",
                "check_crl": "no",
                "syn_scanner": "yes",
                "syn_firewall_detection": "Automatic (normal)",
                "udp_scanner": "no",
                "ssh_netstat_scanner": "yes",
                "wmi_netstat_scanner": "yes",
                "snmp_scanner": "yes",
                "only_portscan_if_enum_failed": "yes",
                "verify_open_ports": "no",
                "unscanned_closed": "no",
                "portscan_range": "default",
                "wol_mac_addresses": "",
                "wol_wait_time": "5",
                "scan_network_printers": "no",
                "scan_netware_hosts": "no",
                "scan_ot_devices": "no",
                "ping_the_remote_host": "yes",
                "arp_ping": "yes",
                "tcp_ping": "yes",
                "tcp_ping_dest_ports": "built-in",
                "icmp_ping": "yes",
                "icmp_unreach_means_host_down": "no",
                "icmp_ping_retries": "2",
                "udp_ping": "no",
                "test_local_nessus_host": "yes",
                "fast_network_discovery": "no",
                "emails": "",
                "filter_type": "and",
                "filters": [],
                "launch_now": False,
                "enabled": False,
                "name": name,
                "description": description,
                "folder_id": 3,
                "scanner_id": "1",
                "text_targets": targets,
                "file_targets": ""
            }
        }
        data = json.dumps(data, separators=(',', ':'))
        response = requests.post(url, headers=self.headers, data=data, verify=False)

        print(response.text)
        print(response)
        return response

    @verify_token
    def start_task(self,task_id):
        """
        启动任务
        """
        api = "https://{ip}:{port}/scans/{scan_id}/launch".format(ip=self.ip, port=self.port, scan_id=task_id)
        response = requests.post(api, verify=False, headers=self.headers)
        if response.status_code != 200:
            return False
        return True

    @verify_token
    def stop_task(self,task_id):
        """
        停止任务
        """
        api = "https://{}:{}/scans/{}/stop".format(self.ip, self.port,task_id)
        response = requests.post(api, headers=self.headers, verify=False)
        if response.status_code == 200 or response.status_code == 409: # 根据nessus api文档可以知道409 表示任务已结束
            return True
        return False




if __name__ == '__main__':
    ip='192.168.111.119'
    port=('8834')
    opt = optNessus(ip,port)
    # token = opt.getNessusToken(ip,port)
    # uuid_ = getScanUuid(token,url_templates)
    # name='test20230309'
    # description='测试添加扫描'
    # targets='192.168.111.120'
    # add_scan(token,url_scan,uuid_,name,description,targets)
    opt.start_task(25,)
    # opt.stop_task(25)


