rule Trojan_Linux_Mirai_2147740141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai!MTB"
        threat_id = "2147740141"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox ESTELLA" ascii //weight: 1
        $x_1_2 = "chmod 777 .load;" ascii //weight: 1
        $x_1_3 = "killall -9 busybox telnetd" ascii //weight: 1
        $x_1_4 = "echo -e \"/bin/busybox telnetd -p9000 -l/bin/sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_SP_2147745811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.SP!MSR"
        threat_id = "2147745811"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_get_opt_int" ascii //weight: 1
        $x_1_2 = "killer_kill_by_port" ascii //weight: 1
        $x_1_3 = "attack_method_std" ascii //weight: 1
        $x_1_4 = "killer_pid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Linux_Mirai_B_2147745823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.B!MTB"
        threat_id = "2147745823"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "attack_method.c" ascii //weight: 1
        $x_1_2 = "attack_kill_all" ascii //weight: 1
        $x_1_3 = "killer_realpath" ascii //weight: 1
        $x_1_4 = "killer_kill_by_port" ascii //weight: 1
        $x_1_5 = "attack_get_opt_ip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_C_2147745826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.C!MTB"
        threat_id = "2147745826"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/lumi/fmw.php?c=" ascii //weight: 1
        $x_1_2 = "/var/tmp/dnssmasq" ascii //weight: 1
        $x_1_3 = "mops" ascii //weight: 1
        $x_1_4 = "/usr/bin/dnssmasq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_A_2147746220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.A!MTB"
        threat_id = "2147746220"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 10 c0 e3 04 20 91 e4 03 30 10 e2 00 00 63 e2 04 00 00 0a ff 20 82 e3 01 30 53 e2 ff 2c 82 c3 01 30 53 e2 ff 28 82 c3 ff 00 12 e3 ff 0c 12 13 ff 08 12 13 ff 04 12 13 04 00 80 12 04 20 91 14 f8 ff ff 1a ff 00 12 e3 01 00 80 12 ff 0c 12 13 01 00 80 12 ff 08 12 13 01 00 80 12 0e f0 a0 e1}  //weight: 2, accuracy: High
        $x_2_2 = "FUCKT/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_G_2147751579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.G!MTB"
        threat_id = "2147751579"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {77 67 65 74 25 32 30 68 74 74 70 25 33 41 25 32 46 25 32 46 [0-16] 25 32 46 73 68 69 69 6e 61 2e 61 72 6d 25 33 42 63 68 6d 6f 64 25 32 30 37 37 37 25 32 30 73 68 69 69 6e 61 2e 61 72 6d}  //weight: 2, accuracy: Low
        $x_1_2 = {77 67 65 74 20 68 74 74 70 3a 2f 2f [0-16] 2f 73 68 69 69 6e 61 2e 73 68}  //weight: 1, accuracy: Low
        $x_1_3 = "GET /shell?cd%20%2Ftmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_L_2147752889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.L!MTB"
        threat_id = "2147752889"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/bin/busybox CORONA" ascii //weight: 1
        $x_1_2 = "Protecting your device from further infections" ascii //weight: 1
        $x_1_3 = "t0talc0ntr0l4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_M_2147757324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.M!MTB"
        threat_id = "2147757324"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmui/locallb/workspace/tmshCmd.jsp" ascii //weight: 1
        $x_1_2 = "/linuxki443/experimental/vis/ki443vis.php" ascii //weight: 1
        $x_1_3 = "diag_ping_admin_en.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_YB_2147761399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.YB!MTB"
        threat_id = "2147761399"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "dotheneedfull.xyz" ascii //weight: 4
        $x_1_2 = "tmp/fetch" ascii //weight: 1
        $x_1_3 = "actionHandler/ajax_network_diagnostic_tools.php" ascii //weight: 1
        $x_1_4 = "smartdomuspad/modules/reporting/track_import_export.php " ascii //weight: 1
        $x_1_5 = "view/IPV6/ipv6networktool/traceroute/ping.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_YC_2147762353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.YC!MTB"
        threat_id = "2147762353"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cnc.devilsden.net/8UsA.sh" ascii //weight: 2
        $x_1_2 = "waninf=1_INTERNET_R_VID" ascii //weight: 1
        $x_1_3 = "/tmp/jno" ascii //weight: 1
        $x_1_4 = "boaform/admin/formPing" ascii //weight: 1
        $x_1_5 = "46.101.157.90/666.sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_SD_2147808331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.SD!xp"
        threat_id = "2147808331"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "U$eS:DZCjEmYxWpt" ascii //weight: 2
        $x_2_2 = "z7uNBc3 a2LT" ascii //weight: 2
        $x_2_3 = "4Q0yXlgAKP6i1VrO" ascii //weight: 2
        $x_2_4 = "/bin/busybox" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_V_2147816313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.V!MTB"
        threat_id = "2147816313"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "knownBots" ascii //weight: 1
        $x_1_2 = "sendUDP" ascii //weight: 1
        $x_1_3 = "sendHTTP" ascii //weight: 1
        $x_1_4 = "dnsflood" ascii //weight: 1
        $x_1_5 = "enemybot" ascii //weight: 1
        $x_1_6 = {5b 6b 69 6c 6c 65 72 5d 20 6b 69 6c 6c 69 6e 67 3a 20 [0-3] 70 69 64 3a}  //weight: 1, accuracy: Low
        $x_5_7 = {63 64 20 2f 76 61 72 2f 72 75 6e 20 7c 7c 20 63 64 20 2f 6d 6e 74 20 7c 7c 20 63 64 20 2f 64 61 74 61 20 7c 7c 20 63 64 20 2f 72 6f 6f 74 20 7c 7c 20 63 64 20 2f 3b 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f [0-9] 20 2d 4f 20 [0-9] 3b 20 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f 25 73 2f [0-9] 20 2d 4f 20 [0-9] 3b 20 63 75 72 6c 20 68 74 74 70 3a 2f 2f 25 73 2f [0-9] 20 2d 4f 20 [0-9] 3b 20 63 68 6d 6f 64 20 37 37 37 20 [0-9] 3b 20 2e 2f [0-9] 3b 20 72 6d 20 2d 72 66}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_AA_2147817789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.AA"
        threat_id = "2147817789"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "qC8cVuGTnRH6cfv7sjcYPFv7guAmZxbQRc57fV77IUUj5b6wocpfFJPmHC" ascii //weight: 2
        $x_2_2 = "lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1VcblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9feBeHdlvMRDLbEbty3Py8yVT3UTjy3ZKONXmMNvURTUZTkeH37XT9H5JwH0vKB1Yw2rSY" ascii //weight: 2
        $x_1_3 = "/etc/config/resolv.conf" ascii //weight: 1
        $x_1_4 = "/etc/config/hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_CC_2147817790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.CC"
        threat_id = "2147817790"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {24 28 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 20 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 2d 6c 20 2f 74 6d 70 2f [0-9] 20 2d 72 20 2f 78 3b 20 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 63 68 6d 6f 64 20 37 37 37 20 2a 20 2f 74 6d 70 2f 73 6b 65 72 65 3b 20 2f 74 6d 70 2f 73 6b 65 72 65 20 68 75 61 77 65 69 29}  //weight: 4, accuracy: Low
        $x_3_2 = "SERVZUXO" ascii //weight: 3
        $x_3_3 = "/var/Sofia" ascii //weight: 3
        $x_2_4 = "/system/system/bin/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_DD_2147817791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.DD"
        threat_id = "2147817791"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "[scanner] Scanner process initialized. Scanning started" ascii //weight: 4
        $x_2_2 = "Attempting to brute found IP" ascii //weight: 2
        $x_2_3 = "[report] Send scan result to loader" ascii //weight: 2
        $x_2_4 = "lost connection with CNC" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_FA_2147818206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.FA"
        threat_id = "2147818206"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DDoS-Attack" ascii //weight: 1
        $x_1_2 = "BOTKILL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_FF_2147818281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.FF"
        threat_id = "2147818281"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/x77/x35/x77/x75/x24/x20/x26/x75/x23/x28/x2A/x34/x2F/x27/x2B/x31/x2C/x2D/x37/x2A/x21/x76/x73/x35/x28/x22/x77/x34/x2E/x74/x77/x20/x73/x2F/x2A/x24/x75/x26/x28/x24/x32/x76/x3F/x72" ascii //weight: 5
        $x_5_2 = "/x20/x29/x73/x26/x76/x74/x27/x37/x37/x36/x36/x37/x32/x71/x30/x29/x28/x2C/x22/x35/x3F/x37/x37/x3F/x76/x20/x31/x3D/x76/x32/x28/x27/x74/x3F/x23/x74/x75/x29/x30/x77/x77/x31/x71/x24/x29/x35/x28/x33/x3F/x26" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_Mirai_HH_2147818282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.HH"
        threat_id = "2147818282"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "/var/Sofia/" ascii //weight: 5
        $x_3_2 = "/bin/busybox dd if=/bin/busybox bs=" ascii //weight: 3
        $x_2_3 = "/bin/busybox chmod 777" ascii //weight: 2
        $x_2_4 = "/bin/busybox cat /proc/cpuinfo" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_II_2147818283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.II"
        threat_id = "2147818283"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93" ascii //weight: 2
        $x_2_2 = "/root/#fuckwhitehats" ascii //weight: 2
        $x_2_3 = "gay fag white hats" ascii //weight: 2
        $x_2_4 = "Binded and listening on address" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_Mirai_B_2147819270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.B!xp"
        threat_id = "2147819270"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rm -rf /mnt/mydir" ascii //weight: 1
        $x_1_2 = "hmod 777 /mnt/mydir/" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
        $x_1_5 = "YRF%6udCJFG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_Mirai_W_2147831779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.W!MTB"
        threat_id = "2147831779"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f4 13 02 b0 61 6a f4 1b c0 b0 60 8a f0 13 02 b0 40 22 44 00 f0 1b 00 b1 40 8a 50 73 05 f2}  //weight: 1, accuracy: High
        $x_1_2 = {f8 13 02 b0 ab e2 0a f4 e4 13 02 b0 61 6a e4 1b c0 b0 40 8a f8 1b 80 b0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Mirai_X_2147906333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.X!MTB"
        threat_id = "2147906333"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "-r /vi/mips.bushido" ascii //weight: 5
        $x_5_2 = "/bin/busybox chmod 777 * /tmp/" ascii //weight: 5
        $x_1_3 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" ascii //weight: 1
        $x_1_4 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" ascii //weight: 1
        $x_1_5 = "POST /cdn-cgi/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_Y_2147908958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.Y!MTB"
        threat_id = "2147908958"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3c 1c 00 05 27 9c ?? ?? 03 99 e0 21 27 bd ff e0 af bf 00 1c af b0 00 18 af bc 00 10 24 02 10 52 00 00 00 0c 8f 99 ?? ?? 10 e0 00 06 00 40 80 21 03 20 f8 09 00 00 00 00 8f bc 00 10 ac 50 00 00 24 02 ff ff 8f bf 00 1c 8f b0 00 18 03 e0 00 08 27 bd 00 20}  //weight: 5, accuracy: Low
        $x_5_2 = {10 00 00 07 00 a2 20 21 15 00 00 05 24 84 00 01 8c c2 00 00 00 00 00 00 24 42 00 01 ac c2 00 00 90 82 00 00}  //weight: 5, accuracy: High
        $x_1_3 = "3o1qdrmfp2juaibch6v8wg57esl0nt4k" ascii //weight: 1
        $x_1_4 = ".mdebug.abi32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_AA_2147908960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.AA!MTB"
        threat_id = "2147908960"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {b8 42 00 00 00 cd 80 89 c2 81 fa 00 f0 ff ff 76 0d b8 f8 ff ff ff f7 da 65 89 10 83 c8 ff}  //weight: 4, accuracy: High
        $x_4_2 = {8b 54 24 04 31 c0 80 3a 00 74 0e 90 8d 74 26 00 83 c0 01 80 3c 10 00 75 f7 f3 c3}  //weight: 4, accuracy: High
        $x_1_3 = "TCP\\rqMDKC" ascii //weight: 1
        $x_1_4 = "lcogqgptgp" ascii //weight: 1
        $x_1_5 = "post /cdn-cgi/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Mirai_LX_2147950973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Mirai.LX!MTB"
        threat_id = "2147950973"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Mirai"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Kill bypass attempt" ascii //weight: 2
        $x_1_2 = "Kill blacklist" ascii //weight: 1
        $x_1_3 = "Missing fds" ascii //weight: 1
        $x_1_4 = "Kill new" ascii //weight: 1
        $x_1_5 = "Deleted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

