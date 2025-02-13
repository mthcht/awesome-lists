rule Backdoor_Win32_Bafruz_B_2147646057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.B"
        threat_id = "2147646057"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "baza-44.ru" ascii //weight: 3
        $x_2_2 = "find_av_ver(rSearchRec.Name, AV_ID, AV_VER)" ascii //weight: 2
        $x_2_3 = "firewall set opmode mode=disable" ascii //weight: 2
        $x_2_4 = "KAV_UNINSTALL" ascii //weight: 2
        $x_3_5 = {78 70 64 72 76 73 64 2e 65 78 65 00}  //weight: 3, accuracy: High
        $x_2_6 = {77 69 6e 73 65 74 75 70 61 70 69 2e 6c 6f 67 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bafruz_E_2147647945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.E"
        threat_id = "2147647945"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "netstat -ano" ascii //weight: 1
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\AuthorizedApplications\\List" ascii //weight: 1
        $x_1_3 = "127.0.0.1 www.login.vk.com" ascii //weight: 1
        $x_1_4 = "DnsServer_11" ascii //weight: 1
        $x_1_5 = "dns/send_p.php?sid=" ascii //weight: 1
        $x_1_6 = "knock.php?ip=" ascii //weight: 1
        $x_2_7 = {ba e8 fd 00 00 b8 10 27 00 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 01 8d 4d}  //weight: 2, accuracy: Low
        $x_2_8 = {b8 17 f6 00 00 e8 ?? ?? ?? ?? 68 88 13 00 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bafruz_I_2147651619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.I"
        threat_id = "2147651619"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "ddos_http_list" ascii //weight: 2
        $x_1_2 = "KAV_START" ascii //weight: 1
        $x_1_3 = {73 74 61 6e 64 00 00 00 6f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {b9 40 42 0f 00 ba 95 b2 00 00 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 84 c0 75}  //weight: 1, accuracy: Low
        $x_1_5 = "w_distrib_iplist.txt" ascii //weight: 1
        $x_1_6 = {ff 52 14 83 f8 0a 7d ?? 6a 50 68 10 27 00 00 6a 01 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bafruz_J_2147656533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.J"
        threat_id = "2147656533"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 7b 0d 00 74 c2 33 c0 19 00 75 0d 53 68 ?? ?? ?? ?? 8b c3 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_1_2 = {77 5f 64 69 73 74 72 69 62 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {4e 4f 44 5f 54 58 54 00 ff ff ff ff 04 00 00 00 65 73 65 74 00}  //weight: 1, accuracy: High
        $x_2_4 = {b9 40 42 0f 00 ba 3b d9 00 00 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 75 ?? c6 05 ?? ?? ?? ?? 00 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bafruz_K_2147657273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.K"
        threat_id = "2147657273"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 84 50 8d 45 80 8b 4d fc ba 0e 00 68 90 1f 00 00 68 10 27 00 00 6a 01 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = "systeminfog" ascii //weight: 1
        $x_2_3 = {73 6f 66 74 5f 6c 69 73 74 00 00 00 ff ff ff ff 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 7c 44 34 31 44 38 43 44 39 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 69 73 74 72 69 62 5f 73 65 72 76}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bafruz_L_2147657274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.L"
        threat_id = "2147657274"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 6b 64 77 2e 70 68 70 3f 73 65 72 69 61 6c 3d 00 00 00 00 ff ff ff ff 04 00 00 00 26 69 64 3d}  //weight: 2, accuracy: High
        $x_1_2 = "l1rezerv.exe" ascii //weight: 1
        $x_1_3 = "l_rezerv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bafruz_A_2147657752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.gen!A"
        threat_id = "2147657752"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "w_distrib.exe" ascii //weight: 1
        $x_1_2 = "sysdriver32_.exe" ascii //weight: 1
        $x_1_3 = "ip_list.txt" ascii //weight: 1
        $x_1_4 = "knock_bad3.php?ver=" ascii //weight: 1
        $x_1_5 = "supercarsinfo.net" ascii //weight: 1
        $x_1_6 = "systeminfog" ascii //weight: 1
        $x_1_7 = "ddos_udp_list" ascii //weight: 1
        $x_1_8 = "ddos_http_list" ascii //weight: 1
        $x_2_9 = {6a 50 68 10 27 00 00 6a 01 6a 00 8d ?? ?? 50 [0-11] b8 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_1_10 = "distrib_serv/ip_list.php" ascii //weight: 1
        $x_1_11 = "Tmonitor_btcd" ascii //weight: 1
        $x_1_12 = {8b 45 08 8b 00 e8 ?? ?? ?? ?? 3d c2 01 00 00 7d ?? 6a 50 68 10 27 00 00 6a 01 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Bafruz_N_2147657917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.N"
        threat_id = "2147657917"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 3d 0d 00 00 e8 ?? ?? ?? ?? 68 60 ea 00 00 e8 ?? ?? ?? ?? 80 7b 0d 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = "ddos_udp_list" ascii //weight: 1
        $x_1_3 = "udp/knock.php?ver=" ascii //weight: 1
        $x_1_4 = "distrib_serv/ip_list.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Bafruz_O_2147657976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bafruz.O"
        threat_id = "2147657976"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bafruz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 50 68 10 27 00 00 6a 01 6a 00 8d ?? ?? 50 8d ?? ?? b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_2_2 = {67 65 74 5f 69 70 5f 70 61 79 5f 6e 65 65 64 62 6c 6f 63 6b [0-5] 2e 70 68 70}  //weight: 2, accuracy: Low
        $x_1_3 = "iecheck_iplist.txt" ascii //weight: 1
        $x_1_4 = "srviecheck" ascii //weight: 1
        $x_1_5 = "TVK_WebServer" ascii //weight: 1
        $x_1_6 = "dns/dns.exe" ascii //weight: 1
        $x_1_7 = "iecheck" ascii //weight: 1
        $x_1_8 = "127.0.0.1 www.login.vk.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

