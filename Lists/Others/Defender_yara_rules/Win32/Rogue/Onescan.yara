rule Rogue_Win32_Onescan_156511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "realcleaner-del" ascii //weight: 1
        $x_1_2 = "realcleaner.co.kr" ascii //weight: 1
        $x_1_3 = "&strPC=%s&strID=%s&strSite=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s.%s/APP/loading.php" ascii //weight: 1
        $x_1_2 = "GetUrlinfo()  ERROR !!  Why? %s" ascii //weight: 1
        $x_1_3 = "firstvaccine.co.kr]\\release\\froductline.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "speedclear.co.kr" ascii //weight: 1
        $x_1_2 = "speedclearU" ascii //weight: 1
        $x_1_3 = "/bill_mobil/bill/ph/step1.php?strPC=%s&strID=%s" ascii //weight: 1
        $x_1_4 = "ping -n 1 -f -l %d %s" ascii //weight: 1
        $x_1_5 = "kornet.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://onescan.co.kr/" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\onescan" ascii //weight: 1
        $x_1_4 = "http://%s.%s/APP/download.php?m=%s&d=%s&a=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://multivaccine.co.kr/reset.php?strPC=%s&strPNO=%s&strSNO=%s" ascii //weight: 10
        $x_10_2 = "SOFTWARE\\multivaccine" ascii //weight: 10
        $x_1_3 = "server response : %s" ascii //weight: 1
        $x_1_4 = "%0.2X:%0.2X:%0.2X:%0.2X:%0.2X:%0.2X" ascii //weight: 1
        $x_1_5 = "[svn]\\[pcprivacy]\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 61 63 63 69 6e 65 [0-16] 72 65 73 65 72 76 61 74 69 6f 6e 00 25 79 25 6d 25 64}  //weight: 1, accuracy: Low
        $x_1_2 = "vaccine_Blocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 6c 6f 63 6b 73 69 74 65 20 77 68 65 72 65 20 75 72 6c 20 6c 69 6b 65 20 27 68 74 74 70 3a 2f 2f 00 00 25 27 3b}  //weight: 1, accuracy: High
        $x_1_2 = {2f 65 74 63 2f 68 61 72 7a 61 72 64 2e 68 74 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d1 fe ff d5 2b c7 6a 05 99 2b c2}  //weight: 10, accuracy: High
        $x_1_2 = "/bill_mobil/" ascii //weight: 1
        $x_1_3 = "/settle.php?" ascii //weight: 1
        $x_1_4 = "?strPC=%s&strID=%s" ascii //weight: 1
        $x_1_5 = "&strSite=%s" ascii //weight: 1
        $x_1_6 = "\\[UserScan-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strPC=%s" ascii //weight: 1
        $x_1_2 = "C:\\temp.ping" ascii //weight: 1
        $x_1_3 = {70 6f 70 75 70 00 00 00 54 52 55 45}  //weight: 1, accuracy: High
        $x_1_4 = ".co.kr" ascii //weight: 1
        $x_1_5 = "login_okok.htm" ascii //weight: 1
        $x_1_6 = "/settle.php?" ascii //weight: 1
        $x_1_7 = "/bill_mobil/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Rogue_Win32_Onescan_156511_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/APP/delete.php?m=%s" ascii //weight: 1
        $x_1_2 = {5c 49 44 43 68 55 6e 69 6e 73 74 61 6c 6c 44 2e 63 70 70 20 00 75 6e 69 6e 73 74 61 6c 6c}  //weight: 1, accuracy: Low
        $x_5_3 = {49 53 4b 49 4d 20 46 72 61 6d 65 77 6f 72 6b 73 20 4c 6f 67 57 6e 64 32 00 00 00 00 b7 ce b1 d7 20 32 2e 30}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 2f 62 69 6c 6c 5f 6d 6f 62 69 6c 2f 63 6c 6f 73 65 57 69 6e 2e 68 74 6d 00 00 00 00 6c 6f 67 69 6e 5f 6f 6b 6f 6b 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 73 65 74 74 6c 65 2e 70 68 70 3f 73 74 72 49 44 3d (00|25 73 26 73 74 72)}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 6e 69 63 00 [0-3] 25 59 2d 25 6d 2d 25 64 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {65 74 63 2f 79 61 6b 5f 61 70 70 2e 68 74 6d 00}  //weight: 3, accuracy: High
        $x_1_2 = {62 75 6e 64 6c 65 5f 73 74 61 74 2e 70 68 70 3f 76 31 3d 25 73 26 76 32 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 50 50 2f 73 74 61 74 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {3f 76 31 3d 25 73 26 76 32 3d 25 73 26 76 33 3d 25 73 26 76 34 3d 25 73 26 76 35 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 6f 64 65 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6f 64 65 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 6c 70 68 61 76 61 63 63 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 00}  //weight: 1, accuracy: High
        $x_1_4 = ".kr/value.php?strMode=delete&strPC=%s&strID=%s&strSite=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bundle.php?v1=%s&v2=%s" ascii //weight: 1
        $x_1_2 = "stat.php?v1=%s&v2=%s&v3=%s&v4=%s" ascii //weight: 1
        $x_1_3 = "bundle_stat.php?v1=%s&v2=%s" ascii //weight: 1
        $x_1_4 = {75 74 69 6c 2f 67 75 69 64 65 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 65 64 69 61 5f 63 6b 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_Onescan_156511_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 69 63 00 [0-3] (53 4f 46 54 57 41 52|25 73 2e 63 6f 2e)}  //weight: 1, accuracy: Low
        $x_5_2 = {2f 76 61 6c 75 65 2e 70 68 70 3f 73 74 72 4d 6f 64 65 3d 64 65 6c 65 74 65 26 73 74 72 50 43 3d [0-5] 25 73 26 73 74 72 49 44 3d 25 73 26 73 74 72 53 69 74 65 3d}  //weight: 5, accuracy: Low
        $x_5_3 = "/reset.php?strPC=%s&strPNO=%s&strSNO=%s" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ef 0c 47 c1 e7 0c 57 89 7e 10 e8 ?? ?? ?? ?? 83 c4 04 89 46 08 8b 4e 10 8b 7e 08 8b d1 33 c0 c1 e9 02 f3 ab}  //weight: 1, accuracy: Low
        $x_1_2 = ".co.kr/APP/stat.php?v1=" ascii //weight: 1
        $x_1_3 = ".co.kr/APP/pf_ck.php?v1=" ascii //weight: 1
        $x_1_4 = "N0lYWDdsd392dHdpbDZ4cHhHdUU=" ascii //weight: 1
        $x_1_5 = "mbk.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 62 6f 6f 74 00 00 32 00 00 00 [0-4] 69 6e 73 74 61 6c 6c 6d 6f 64 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 63 6f 2e 6b 72 2f 76 65 72 73 69 6f 6e 00 [0-3] 5f 75 70 64 61 74 65 72 5f 61 67 65 6e 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {75 70 64 61 74 65 00 00 75 6e 69 6e 73 74 5f 18 00 2e 65 78 65 00 [0-3] 76 65 72 31 00 [0-48] 00 76 65 72 25 64 00 00 00 25 73 25 73 00 00 00 00 00 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {70 68 70 3f 73 74 72 50 43 3d 25 73 26 73 74 72 50 4e 4f 3d 25 73 26 73 74 72 53 4e 4f 3d 25 73 00}  //weight: 10, accuracy: High
        $x_10_2 = {63 58 78 70 65 48 68 31 4e 6d 74 33 64 51 3d 3d 00}  //weight: 10, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 75 70 72 6f 74 65 63 74 2e 63 6f 2e 6b 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 75 70 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 75 72 62 6f 56 61 63 63 69 6e 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {6f 6e 65 73 74 6f 70 76 61 63 63 69 6e 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 70 64 61 74 65 44 61 79 [0-8] 25 59 2d 25 6d 2d 25 64}  //weight: 1, accuracy: Low
        $x_1_2 = {25 73 25 73 22 20 75 70 64 61 74 65 00 00 00 76 65 72 31 00 00 00 00 76 65 72 25 64 00 00 00 22 25 73 25 73 22 20 25 73 00 00 00 22 25 73 25 73}  //weight: 1, accuracy: High
        $x_1_3 = {52 65 62 6f 6f 74 00 00 32 00 00 00 31 00 00 00 53 4f 46 54 57 41 52 45}  //weight: 1, accuracy: High
        $x_1_4 = {2e 63 6f 2e 6b 72 2f 62 69 6e 2f 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 63 6f 2e 6b 72 2f 76 65 72 73 69 6f 6e 2f 62 69 6e 61 2f 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_Onescan_156511_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 74 63 2f 79 61 6b 5f 61 70 70 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {41 50 50 2f 70 66 5f 63 6b 2e 70 68 70 3f 76 31 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "&strID=%s&strPC=%s|%s&strSite=" ascii //weight: 1
        $x_1_4 = {3f 76 31 3d 25 73 26 76 32 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 65 73 74 5f 68 49 6e 74 65 72 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "http://%s/P/%s" ascii //weight: 1
        $x_1_7 = "vaccine_install" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_Onescan_156511_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 72 2f 41 50 50 2f 73 74 61 74 2e 70 68 70 3f 76 31 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 77 61 74 65 72 00 00 00 6d 75 74 65 78 5f 69 6e 73 74 61 6c 6c 5f}  //weight: 1, accuracy: High
        $x_1_3 = {6b 5f 61 70 70 00 00 00 2f 79 61 00 74 63 00 2f 65 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 65 73 74 5f 68 49 6e 74 65 72 6e 65 74 00 00 64 62 6b 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {77 69 6e 64 6f 77 67 75 61 72 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {77 69 6e 64 6f 77 67 75 61 72 64 75 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_Onescan_156511_21
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 75 74 65 78 5f 73 6f 6c 75 74 69 6f 6e 70 63 2d 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {76 31 3d 25 73 00 00 2f 6d 62 6b 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 6f 6c 75 74 69 6f 6e 70 63 73 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 73 74 72 50 43 3d 00 2f 76 61 6c 75 65 2e 70 68 70 3f 73 74 72 4d 6f 64 65 3d 73 65 74 75 70 26 73 74 72 49 44 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 79 61 6b 5f 61 70 70 00}  //weight: 1, accuracy: High
        $x_1_6 = ".kr/APP/stat.php?v1=" ascii //weight: 1
        $x_1_7 = ".kr/APP/pf_ck.php?v1=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_Onescan_156511_22
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Micropop\\" ascii //weight: 1
        $x_1_2 = {75 70 64 61 74 65 44 61 79 [0-8] 25 59 2d 25 6d 2d 25 64}  //weight: 1, accuracy: Low
        $x_1_3 = {49 73 50 6f 70 55 70 00 25 73 25 73 5c 64 6f 77 6e 2e 6a 70 67}  //weight: 1, accuracy: High
        $x_1_4 = "/APP/stat.php?v1=%s&v2=%s&v3=%s" ascii //weight: 1
        $x_1_5 = {25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 00}  //weight: 1, accuracy: High
        $x_1_6 = {2e 63 6f 2e 6b 72 2f 61 64 6d 69 6e 2f 74 6f 70 2f 70 6f 70 75 70 [0-1] 2f 70 6f 70 5f 6c 61 79 65 72 [0-1] 2e 68 74 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_Onescan_156511_23
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 6e 65 73 63 61 6e 2e 63 6f 2e 6b 72 2f 07 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_2_2 = {75 70 64 61 74 65 2e 6f 6e 65 73 63 61 6e 2e 63 6f 2e 6b 72 2f 07 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_1_3 = {65 74 63 2f 79 61 6b 5f 61 70 70 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = "mbk.php?v1=%s&v2=%s" ascii //weight: 1
        $x_1_5 = "value.php?strMode=setup&strID=%s" ascii //weight: 1
        $x_1_6 = {25 73 2f 50 2f 25 73 07 00 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
        $x_1_7 = "software\\onescan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_24
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "settle.php?strID=%s&strPC=%s&strSite=" ascii //weight: 1
        $x_1_2 = "value.php?strMode=run&strID=%s&strPC=%s" ascii //weight: 1
        $x_1_3 = "bill_mobil/bill/ph/step1.php?strPC=%s&strID=%s&strSite=%s" ascii //weight: 1
        $x_1_4 = {6c 6f 67 69 6e 5f 6f 6b 6f 6b 2e 68 74 6d 00}  //weight: 1, accuracy: High
        $x_1_5 = "insert into blocksite (url) values('%s');" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_Onescan_156511_25
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 62 6f 6f 74 00 00 32 00 00 00 31 00 00 00 53 4f 46 54 57 41 52 45 5c}  //weight: 1, accuracy: High
        $x_1_2 = {00 69 6e 73 74 61 6c 6c 6d 6f 64 65 00 30 15 00 32 00 00 00 31 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 64 61 74 61 3a 00 00 70 77 64 61 74 61 3a 00 70 65 72 73 6f 6e 61 6c 64 61 74 61 3a 00 00 00 63 6f 75 6e 74 64 61 74 61 3a}  //weight: 1, accuracy: High
        $x_5_4 = {49 53 4b 49 4d 20 46 72 61 6d 65 77 6f 72 6b 73 20 4c 6f 67 57 6e 64 32 00 00 00 00 b7 ce b1 d7 20 32 2e 30}  //weight: 5, accuracy: High
        $x_1_5 = {76 61 63 63 69 6e 65 6f 6e 2e 63 6f 2e 6b 72 2f 76 65 72 73 69 6f 6e 2f 76 65 72 73 69 6f 6e 00 00 00 76 61 63 63 69 6e 65 6f 6e 5f 61 67 65 6e 63 79 00 00 00 00 5c 76 61 63 63 69 6e 65 6f 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_26
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 0c 33 f6 8b 79 f8 85 ff 7e 19 8b 54 24 0c 8d 4c 24 0c 8a 04 16 2c 08 50 56 e8 ?? ?? ?? ?? 46 3b f7 7c e7}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 04 89 46 08 8b 4e 10 8b 7e 08 8b d1 33 c0 c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa}  //weight: 1, accuracy: High
        $x_1_3 = "[UCF]\\[plusguard.co.kr]" ascii //weight: 1
        $x_1_4 = "%s.%s/APP/loading.php" ascii //weight: 1
        $x_1_5 = "-Mac-Change-ex" ascii //weight: 1
        $x_1_6 = {b8 c5 b3 a2 91 f7 e9 03 d1 c1 fa 0b 8b c2 c1 e8 1f 03 d0 85 d2}  //weight: 1, accuracy: High
        $x_1_7 = {76 61 63 63 69 6e 65 [0-8] 5f 6e 69 63}  //weight: 1, accuracy: Low
        $x_1_8 = "GetUrlinfo()  ERROR !!  Why? %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_Onescan_156511_27
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 89 46 08 8b 4e 10 8b 7e 08 8b d1 33 c0 c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 62 6f 61 6e [0-8] 2e 63 6f 2e 6b 72 2f 41 50 50 2f [0-10] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_3 = {00 6d 75 74 65 78 5f}  //weight: 1, accuracy: High
        $x_1_4 = {25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 49 6e 74 65 72 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\boan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Onescan_156511_28
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/etc/yak_app.htm" ascii //weight: 2
        $x_1_2 = "%0.2X:%0.2X:%0.2X:%0.2X:%0.2X:%0.2X" ascii //weight: 1
        $x_2_3 = {5f 6e 69 63 [0-32] 69 6e 73 74 61 6c 6c 6d 6f 64 65 [0-4] 63 6f 64 65 31 [0-4] 53 4f 46 54 57 41 52 45 5c}  //weight: 2, accuracy: Low
        $x_1_4 = "?v1=%s&v2=%s" ascii //weight: 1
        $x_2_5 = "http://%s/dbk.php" ascii //weight: 2
        $x_2_6 = ".co.kr/mbk.php" ascii //weight: 2
        $x_2_7 = "value.php?strmode=setup&strid=%s" ascii //weight: 2
        $x_2_8 = {6d 62 6b 2e 70 68 70 00 68 74 74 70 3a 2f 2f [0-16] 63 6f 2e 6b 72 2f 00}  //weight: 2, accuracy: Low
        $x_2_9 = "http://%s/P/%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_29
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 69 6e 64 6f 77 67 75 61 72 64 73 74 61 72 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {6b 72 2f 76 65 72 73 69 6f 6e 2f 76 65 72 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = ".windowguard.co." ascii //weight: 1
        $x_1_4 = {77 69 6e 64 6f 77 67 75 61 72 64 5f 61 67 65 6e 63 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {c6 44 24 21 73 c6 44 24 23 61 c6 44 24 24 72 c6 44 24 26 75 c6 44 24 27 70 be}  //weight: 1, accuracy: High
        $x_1_6 = {80 f9 2d 74 35 80 f9 40 75 21 8b 7c 24 14}  //weight: 1, accuracy: High
        $x_1_7 = {eb 05 80 f9 7c 74 2e 46 43 42 83 fa 64 7c c1 eb 4b 8d 7d 60}  //weight: 1, accuracy: High
        $x_1_8 = {c6 44 24 50 61 c6 44 24 53 6d c6 44 24 54 6f c6 44 24 55 64 c6 44 24 56 65 c6 44 24 57 00}  //weight: 1, accuracy: High
        $x_1_9 = {eb 04 3c 7c 74 12 8b 44 24 1c 45 42 40 83 f8 64 89 44 24 1c 7c c4 eb 18 8b}  //weight: 1, accuracy: High
        $x_1_10 = {22 25 73 25 73 22 20 75 70 64 61 74 65 ?? ?? ?? 76 65 72 31 ?? ?? ?? ?? 76 65 72 25 64 00 00 00 22 25 73 25 73 22 20 25 73 00 00 00 22 25 73 25 73 22}  //weight: 1, accuracy: Low
        $x_1_11 = {52 65 62 6f 6f 74 00 [0-9] 69 6e 73 74 61 6c 6c 6d 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_12 = {62 6f 61 6e [0-11] 5f 61 67 65 6e 63 79 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Rogue_Win32_Onescan_156511_30
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4c 24 0c 33 f6 8b 79 f8 85 ff 7e 19 8b 54 24 0c 8d 4c 24 0c 8a 04 16 2c 08 50 56 e8 ?? ?? ?? ?? 46 3b f7 7c e7}  //weight: 10, accuracy: Low
        $x_10_2 = "/APP/pf_ck.php?v1=" ascii //weight: 10
        $x_10_3 = {2f 79 61 6b 5f 61 70 70 2e 68 74 6d 00}  //weight: 10, accuracy: High
        $x_1_4 = {69 6e 73 74 61 6c 6c 6d 6f 64 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {4e 6f 52 65 70 61 69 72 00 00 00 00 4e 6f 4d 6f 64 69 66 79 00 00 00 00 44 69 73 70 6c 61 79 49 63 6f 6e 00 55 6e 69 6e 73 74 61 6c 6c 53 74 72 69 6e 67 00 55 52 4c 49 6e 66 6f 41 62 6f 75 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {c7 c1 b7 ce b1 d7 b7 a5 5c}  //weight: 1, accuracy: High
        $x_1_7 = "dbk.php" ascii //weight: 1
        $x_1_8 = {c8 a8 c6 e4 c0 cc c1 f6 2e 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = "/APP/download.php?m=%s&d=%s&a=%s" ascii //weight: 1
        $x_1_10 = "/APP/stat.php?v1=" ascii //weight: 1
        $x_1_11 = "mbk.php" ascii //weight: 1
        $x_1_12 = "fXh7fGl8Nn" ascii //weight: 1
        $x_1_13 = "N0lYWDd" ascii //weight: 1
        $x_1_14 = {74 65 73 74 5f 68 49 6e 74 65 72 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 6d 75 74 65 78 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_31
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "etc/yak_app.htm" ascii //weight: 10
        $x_1_2 = "value.php?strMode=setup&strID=%s&strPC=%s" ascii //weight: 1
        $x_1_3 = "setup.php?m=%s&d=%s&a=%s" ascii //weight: 1
        $x_1_4 = "download.php?m=%s&d=%s&a=%s" ascii //weight: 1
        $x_1_5 = "stat.php?v1=%s&v2=%s&v3=%s&v4=%s" ascii //weight: 1
        $x_1_6 = "stat.php?v1=%d&v2=%s&v3=%s&v4=%s" ascii //weight: 1
        $x_1_7 = {6c 69 76 65 73 61 66 65 72 5f 6e 69 63 00}  //weight: 1, accuracy: High
        $x_1_8 = "bundle_stat.php?v1=%s&v2=%s" ascii //weight: 1
        $x_1_9 = {bc b3 c4 a1 2e 2e 2e 00 [0-16] b0 fc b7 c3 20 52 65 67 69 73 74 72 79 20 b0 aa 20 b5 ee b7 cf 00}  //weight: 1, accuracy: Low
        $x_1_10 = "/version/bin" ascii //weight: 1
        $x_1_11 = "value.php?v1=%s&v2=%s&v3=setup&v4=" ascii //weight: 1
        $x_1_12 = {73 6d 61 72 74 76 61 63 63 69 6e 65 5f 6e 69 63 00}  //weight: 1, accuracy: High
        $x_1_13 = "mbk.php?v1=%s&v2=%s" ascii //weight: 1
        $x_1_14 = {76 70 72 6f 74 65 63 74 6f 72 5f 6e 69 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_32
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 6d 61 69 6e 00 [0-3] 6c 6f 67 69 6e 5f 6f 6b 6f 6b 2e 68 74 6d 00}  //weight: 1, accuracy: Low
        $x_1_2 = ".co.kr/settle_button.php?SB=sb" ascii //weight: 1
        $x_1_3 = {2f 76 65 72 73 69 6f 6e 2f 65 78 63 70 5f 69 6e 66 6f [0-1] 00}  //weight: 1, accuracy: Low
        $x_1_4 = "/bill_mobil/bill/ph/step1.php" ascii //weight: 1
        $x_1_5 = {5f 61 67 65 6e 63 79 00 [0-3] 25 73 74 65 6d 70 5c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {70 69 6e 67 20 2d 6e 20 31 20 2d 66 20 2d 6c 20 25 64 20 25 73 00 00 00 6b 6f 72 6e 65 74 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 63 6f 2e 6b 72 2f 65 78 63 70 5f 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 61 69 6e 00 18 00 20 6d 00 [0-3] 6c 6f 67 69 6e 5f 6f 6b 6f 6b 2e 68 74 6d 00}  //weight: 1, accuracy: Low
        $x_1_9 = {3a 2f 2f 75 70 64 61 74 65 2e 18 00 2e 63 6f 2e 6b 72 2f 76 65 72 73 69 6f 6e 2f 62 69 6e 61 2f 00 50 00 00 20 75 70 64 61 74 65 00 00 75 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 63 6f 2e 6b 72 2f 76 65 72 73 69 6f 6e 2f 65 78 63 65 70 74 2f 65 78 63 70 5f 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_11 = "/report.php?strSubject=%s&strEmail=%s&strComm=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Rogue_Win32_Onescan_156511_33
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 72 2f 41 50 50 2f 73 74 61 74 2e 70 68 70 3f 76 31 3d (00|25 64 26 76 32 3d 25 73 26 76 33 3d)}  //weight: 1, accuracy: Low
        $x_1_2 = {68 70 3f 76 31 3d 00 00 63 6b 72 2f 41 50 50 2f 73 74 61 74 2e 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {79 61 6b 5f 61 70 70 2e 68 00 [0-4] 65 74 63}  //weight: 1, accuracy: Low
        $x_1_4 = {5f 6e 69 63 00 [0-16] 03 0b 06 05 69 6e 73 74 61 6c 6c 6d 6f 64 65 52 65 62 6f 6f 74 63 6f 64 65 31 00}  //weight: 1, accuracy: Low
        $x_1_5 = {25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 [0-3] 25 30 2e 32 58 3a 25 30 2e 32 58 3a 25 30 2e 32 58 [0-2] 00 74 65 73 74 5f 68 49 6e 74 65 72 6e 65 74 00}  //weight: 1, accuracy: Low
        $x_1_6 = {00 77 61 74 65 72 00 00 00 6d 75 74 65 78 5f 69 6e 73 74 61 6c 6c 5f}  //weight: 1, accuracy: High
        $x_1_7 = {00 6d 75 74 65 78 5f 18 00 5f 69 6e 73 74 61 6c 6c 00 [0-3] 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {00 65 61 73 79 62 6f 61 6e 2d 69 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = "kr/APP/pf_ck.php?v1=" ascii //weight: 1
        $x_1_10 = {00 6d 75 74 65 78 5f 69 6e 73 74 61 6c 6c 5f 18 00 00 [0-24] 00}  //weight: 1, accuracy: Low
        $x_1_11 = {00 6d 75 74 65 78 5f 69 6e 73 74 61 6c 6c 5f 18 00 00 18 00 00}  //weight: 1, accuracy: Low
        $x_1_12 = {00 6b 5f 61 70 70 00 00 00 2f 79 61 00 74 63 00 00 2f 65 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 2e 70 68 70 3f 76 31 3d 25 64 26 76 32 3d 25 73 26 76 33 3d 25 73 26 76 34 3d 25 73 26 76 35 3d 25 73 26 76 36 3d 25 73 26 76 37 3d 25 73 26 76 38 3d 25 73 00 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e [0-24] 6b 72 2f 41 50 50 2f 73 74 61 74}  //weight: 1, accuracy: Low
        $x_1_14 = {00 6d 75 74 65 78 5f 69 6e 73 74 61 6c 6c 65 72 5f 18 00 00 18 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_Onescan_156511_34
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5f 42 6c 6f 63 6b 65 72 00 [0-3] 06 00 12 00 00 19 00 00 01 02 00}  //weight: 3, accuracy: Low
        $x_3_2 = {42 6c 6f 63 6b 65 72 00 35 00 00 06 00 12 00 00 [0-3] 01 02 5f}  //weight: 3, accuracy: Low
        $x_3_3 = {42 6c 6f 63 6b 65 72 00 35 00 00 06 00 12 00 00 [0-3] 6d 75 74 65 78 5f 01 02 5f}  //weight: 3, accuracy: Low
        $x_3_4 = {73 74 61 72 74 65 72 00 35 00 00 06 00 12 00 00 [0-3] 01 02 5f}  //weight: 3, accuracy: Low
        $x_3_5 = {00 6d 75 74 65 78 5f 06 00 12 00 5f 73 74 61 72 74 65 72 00 [0-3] 00 01 00}  //weight: 3, accuracy: Low
        $x_2_6 = {00 69 6e 73 70 65 63 74 54 69 00 69 6e 73 70 65 63 74 44 61 79 00}  //weight: 2, accuracy: Low
        $x_2_7 = {72 65 73 65 72 76 61 74 69 6f 6e 00 25 79 25 6d 25 64 00}  //weight: 2, accuracy: High
        $x_2_8 = {75 2e 65 78 65 00 [0-3] 2f 73 65 61 72 63 68 32 00}  //weight: 2, accuracy: Low
        $x_2_9 = {2f 73 65 61 72 63 68 32 00 [0-3] 5c 06 00 12 00 75 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_10 = {00 70 65 63 74 54 69 00 00 00 00 69 6e 73 00 69 6e 73 70 65 63 74 44 61 79 00}  //weight: 2, accuracy: Low
        $x_2_11 = {2f 73 65 61 72 63 68 32 00 [0-3] 75 2e 65 78 65 00}  //weight: 2, accuracy: Low
        $x_2_12 = {2f c6 44 24 ?? 73 c6 44 24 ?? 65 c6 44 24 ?? 61 c6 44 24 ?? 72 c6 44 24 ?? 63 c6 44 24 ?? 68 c6 44 24 ?? 32 c6 44 24 ?? 00}  //weight: 2, accuracy: Low
        $x_1_13 = {b0 65 b1 72 88 44 24 ?? 88 44 24 ?? 88 4c 24 ?? 88 4c 24}  //weight: 1, accuracy: Low
        $x_1_14 = {73 c6 44 24 ?? 76 c6 44 24 ?? 61 c6 44 24 ?? 74 c6 44 24 ?? 69 c6 44 24 ?? 6f c6 44 24 ?? 6e c6 44 24 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_Onescan_156511_35
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Onescan"
        threat_id = "156511"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Onescan"
        severity = "113"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 46 1c 6a 00 6a 0a 6a 01 50 c7 86 03 01 01 01 6c 70 80 28 00 00 01 00 00 00 c7 86 03 01 01 01 64 68 78 69 00 00 00 00 00 00 ff 15}  //weight: 3, accuracy: Low
        $x_2_2 = {6b 72 2f 76 65 72 73 69 6f 6e 2f 76 65 72 73 69 6f 6e 32 00}  //weight: 2, accuracy: Low
        $x_2_3 = {61 6e 79 63 6f 70 2e 63 6f 6d 2f 76 65 72 73 69 6f 6e 2f 76 65 72 73 69 6f 6e 00}  //weight: 2, accuracy: High
        $x_2_4 = {76 65 72 73 69 6f 6e 2f 62 69 6e 61 32 2f 25 73 00}  //weight: 2, accuracy: Low
        $x_2_5 = {62 69 6e 61 2f 00 00 00 76 65 72 73 69 6f 6e 2f 00 00 00 00 68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e}  //weight: 2, accuracy: Low
        $x_1_6 = {52 65 62 6f 6f 74 00 00 32 00 00 00 [0-4] 69 6e 73 74 61 6c 6c 6d 6f 64 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {52 65 62 6f 6f 74 00 00 69 6e 73 74 61 6c 6c 6d 6f 64 65 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {00 2f 73 74 61 72 74 75 70 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {5f 61 67 65 6e 63 79 00}  //weight: 1, accuracy: High
        $x_1_10 = {5f 75 70 64 61 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_11 = {76 65 72 73 69 6f 6e 2f 76 65 72 73 69 6f 6e 00 68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e}  //weight: 1, accuracy: High
        $x_1_12 = {22 25 73 25 73 22 20 75 70 64 61 74 65 00 00 00 76 65 72 31 00 00 00 00 76 65 72 25 64}  //weight: 1, accuracy: High
        $x_2_13 = {73 74 61 72 74 2e 65 78 65 00 75 70 64 61 74 65 00 00 61 67 65 6e 63 79 00}  //weight: 2, accuracy: High
        $x_3_14 = {00 75 70 74 00 2f 73 74 61 72 74 00 00 61 67 65 6e 63 79 00}  //weight: 3, accuracy: High
        $x_2_15 = {73 74 61 72 74 2e 65 78 65 00 [0-3] 22 25 73 25 73 22 00 [0-24] 00 75 70 64 61 74 65 00 00 75 70 74 00 2f 73 74 61 72 74 00}  //weight: 2, accuracy: Low
        $x_2_16 = {00 61 67 65 6e 63 79 00 00 2f 76 65 72 73 69 6f 6e 00 00 00 00 68 74 74 70 3a 2f 2f 75 70 64 61 74 65 2e}  //weight: 2, accuracy: High
        $x_2_17 = {2f c6 44 24 ?? 73 c6 44 24 ?? 74 c6 44 24 ?? 61 c6 44 24 ?? 72 c6 44 24 ?? 74 c6 44 24 ?? 75 c6 44 24 ?? 70 c6 44 24 ?? 74}  //weight: 2, accuracy: Low
        $x_2_18 = {69 c6 44 24 ?? 6e c6 44 24 ?? 73 c6 44 24 ?? 74 c6 44 24 ?? 61 c6 44 24 ?? 6d c6 44 24 ?? 6f c6 44 24 ?? 64 c6 44 24 ?? 65}  //weight: 2, accuracy: Low
        $x_2_19 = {76 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 73 c6 44 24 ?? 69 c6 44 24 ?? 6f c6 44 24 ?? 6e}  //weight: 2, accuracy: Low
        $x_2_20 = {b0 74 c6 44 24 ?? 2f 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? c6 44 24 ?? 73 c6 44 24 ?? 61 c6 44 24 ?? 72 c6 44 24 ?? 75 c6 44 24 ?? 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

