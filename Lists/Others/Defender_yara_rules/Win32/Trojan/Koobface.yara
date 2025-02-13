rule Trojan_Win32_Koobface_A_137848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!A"
        threat_id = "137848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 85 38 fe ff ff 68 00 01 00 00 50 ff 75 fc}  //weight: 2, accuracy: High
        $x_1_2 = "topening 7" ascii //weight: 1
        $x_1_3 = "ST%srre" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_B_137849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!B"
        threat_id = "137849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 00 ff ff ff 56 50 53 ff 15 ?? ?? ?? ?? 8d 45 08 56 50 68 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {59 0f 84 35 04 00 00 8b 3d ?? ?? ?? ?? 6a 3d ff 75 0c ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = "uptime=%ld&v=" ascii //weight: 1
        $x_1_4 = "websrv" ascii //weight: 1
        $x_1_5 = {62 6c 64 6f 25 6c 64 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_6 = "?newver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Koobface_C_137850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!C"
        threat_id = "137850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 7c ff 75 f8 ff ?? 59 3b c3 59}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 02 ff d7 53 a3 ?? ?? ?? ?? ff 75 fc 68 ?? ?? ?? ?? ff 75 fc ff d6 50 6a 07}  //weight: 2, accuracy: Low
        $x_1_3 = "/cap/?a=get" ascii //weight: 1
        $x_1_4 = {63 61 70 74 63 68 61 2e 64 6c 6c 00 63 61 70 74 63 68 61 00 6b 62 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_D_138410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!D"
        threat_id = "138410"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET /vx/?uptime=%ld&v=%d&sub=%d&ping=%ld HTTP/1.0" ascii //weight: 1
        $x_1_2 = "netsh firewall add portopening TCP 80 %s ENABLE" ascii //weight: 1
        $x_1_3 = "netsh add allowedprogram \"%s\" %s ENABLE" ascii //weight: 1
        $x_1_4 = "<!-- LABEL_CODEC -->" ascii //weight: 1
        $x_1_5 = "\\websrvx\\websrvx.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Koobface_F_143242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!F"
        threat_id = "143242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 51 70 8b 45 ?? 3b ?? 74 0d 8b ?? 94 01 00 00 8b 08 52 50 ff 51 68 06 00 90 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 91 e0 00 00 00 8b 45 ec (46|47) 81 (fe|ff) 04 01 00 00 7e 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {49 46 45 58 49 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {42 4c 41 43 4b 4c 41 42 45 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Koobface_G_143837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!G"
        threat_id = "143837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 1c 6a 7c 50 c6 45 ?? 01 ff 15 ?? ?? ?? ?? 59 3b c3 59 74 09 40 50}  //weight: 2, accuracy: Low
        $x_2_2 = {42 83 c1 04 83 fa 03 72 eb 85 c0 74 07 03 04 b5}  //weight: 2, accuracy: High
        $x_1_3 = "/cap/?a=query" ascii //weight: 1
        $x_1_4 = "/cap/?a=save" ascii //weight: 1
        $x_1_5 = "/goo/?a=%s" ascii //weight: 1
        $x_1_6 = "/googlereader/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_H_143838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!H"
        threat_id = "143838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 22 8b c7 c6 06 25 8b 0d ?? ?? ?? ?? 46 c1 e8 04 8a 04 08 88 06}  //weight: 2, accuracy: Low
        $x_1_2 = "dump.php?v=" ascii //weight: 1
        $x_1_3 = {6c 2e 70 68 70 3f 75 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "Be careful" ascii //weight: 1
        $x_1_5 = "/check/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_I_144181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!I"
        threat_id = "144181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 79 11 00 00 b9 ff 00 00 00 33 c0 8d bc 24 14 02 00 00 33 db f3 ab 66 ab aa 53 8d 84 24 18 02 00 00 6a 1a}  //weight: 1, accuracy: High
        $x_1_2 = {8d 85 50 ff ff ff 53 50 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 85 a0 fe ff ff 68 ?? ?? ?? ?? 50 c6 85 ?? ?? ?? ?? 68 c6 85 ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Koobface_J_147417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!J"
        threat_id = "147417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 6e 0c 6a 7c 55 ff 15 19 00 6a 0b 68}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 02 ff d7 53 a3 ?? ?? ?? ?? ff 75 fc 68 ?? ?? ?? ?? ff 75 fc ff d6 50 6a 07 ff d7 8b 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? 53 53 8d 45 e0 53 50 ff d6 5f 85 c0 74 15}  //weight: 2, accuracy: Low
        $x_2_3 = {53 50 6a 48 68 9d 01 00 00 53 53 ff b6 ?? ?? 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {6a 07 50 ff 15 ?? ?? ?? ?? 6a 44 8d 45 a0 56 50 e8 ?? ?? ?? ?? 6a 10 8d 45 e4 56 50 c7 45 a0 44 00 00 00 c7 45 cc 01 00 00 00 66 89 75 d0 e8}  //weight: 2, accuracy: Low
        $x_1_5 = {25 73 5c 63 61 25 73 61 25 73 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 73 5c 63 61 70 25 73 2e 62 25 73 00}  //weight: 1, accuracy: High
        $x_1_7 = "?action=captcha" ascii //weight: 1
        $x_1_8 = {72 75 6e 64 6c 6c 20 22 25 73 22 2c 63 61 70 74 63 68 61 00}  //weight: 1, accuracy: High
        $x_1_9 = "Global\\CAPTCHA-" ascii //weight: 1
        $x_1_10 = "%s -k captcha" ascii //weight: 1
        $x_1_11 = "netsh firewall add allowedprogram name=\"captcha\" program=\"%s\" mode=ENABLE" ascii //weight: 1
        $x_1_12 = "%%temp%%\\captcha.bat" ascii //weight: 1
        $x_1_13 = "%%windir%%\\system32\\captcha.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_L_147798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!L"
        threat_id = "147798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8d 4d fc 6a 00 51 ff d0 85 c0 74 0a f6 45 fc 07 74 04 b0 01}  //weight: 4, accuracy: High
        $x_2_2 = {83 c3 0b 8b c7 2b c3}  //weight: 2, accuracy: High
        $x_1_3 = "fbcheck" ascii //weight: 1
        $x_1_4 = "gcheckgen" ascii //weight: 1
        $x_2_5 = "&crc=%d" ascii //weight: 2
        $x_1_6 = "%s?a%sn=%sgen&v=%s&" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_M_148419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!M"
        threat_id = "148419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3f 61 63 74 69 6f 6e 3d 62 73 26 76 3d 32 30 26 61 3d (6e 61 6d|67 65 74 75 6e 72 65 61)}  //weight: 1, accuracy: Low
        $x_1_2 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0a 20 64 65 6c 20 22 25 73 22}  //weight: 1, accuracy: High
        $x_1_3 = {62 6c 6f 67 [0-16] 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_4 = "#BLACKLABEL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Koobface_O_155186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!O"
        threat_id = "155186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 83 c1 04 83 fa 03 72 eb 85 c0 74 07 03 04 b5}  //weight: 2, accuracy: High
        $x_2_2 = {6a 7c 56 89 01 ff 15 ?? ?? ?? ?? 8b f0 83 c4 0c 3b f3 74 ?? 46}  //weight: 2, accuracy: Low
        $x_1_3 = "?action=bitly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_P_155187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!P"
        threat_id = "155187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4f 04 83 c7 04 85 c9 89 7c 24 ?? 8b c7 0f 85 ?? ?? ?? ?? eb ?? 56}  //weight: 1, accuracy: Low
        $x_1_2 = "?action=plgen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Koobface_G_155681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.G"
        threat_id = "155681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 db 53 53 68 97 1f 00 00 e8}  //weight: 1, accuracy: High
        $x_10_2 = "PO%s/que%sv=%d&u=%ld&q=%s%sTP%s.0%sH%st:%c%s%s%sr-A%st: %s%c" ascii //weight: 10
        $x_1_3 = "ru%sl3%s%s\",Se%seMa%sins%sl %s" ascii //weight: 1
        $x_1_4 = {75 0f 47 83 c6 32 3b 7c 24 90 03 01 01 10 14 7c e5}  //weight: 1, accuracy: High
        $x_1_5 = "s%seat%s\"%s\" ty%sinter%sype%sare st%s= aut%snpat%s\"%s -k %s\"%c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_H_155854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.H"
        threat_id = "155854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 6d 73 20 69 65 20 66 74 70 20 70 61 73 73 77 6f 72 64 73 00 [0-16] 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f}  //weight: 2, accuracy: Low
        $x_1_2 = "user@smartftp.com" ascii //weight: 1
        $x_1_3 = {00 53 6f 66 74 77 61 72 65 5c 46 69 6c 65 5a 69 6c 6c 61 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 74 70 6c 69 73 74 2e 74 78 74 [0-16] 41 6e 6f 6e 79 6d 6f 75 73 3d 30}  //weight: 1, accuracy: Low
        $x_1_5 = {3b 55 73 65 72 3d 00 [0-16] 50 61 73 73 77 6f 72 64 3d 00 [0-16] 00 3b 50 6f 72 74 3d 00 [0-16] 53 65 72 76 65 72 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_R_155928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!R"
        threat_id = "155928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 7c 56 89 02 e8}  //weight: 1, accuracy: High
        $x_1_2 = "?action=googgen" ascii //weight: 1
        $x_1_3 = {74 68 65 67 6f 6f 67 2e 74 6d 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Koobface_Q_163470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!Q"
        threat_id = "163470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?post=true&path=blogreg&v=" ascii //weight: 1
        $x_1_2 = "?post=true&path=captcha&v=" ascii //weight: 1
        $x_1_3 = "a=save&b=goo" ascii //weight: 1
        $x_1_4 = {23 57 48 49 54 45 4c 41 42 45 4c 00}  //weight: 1, accuracy: High
        $x_2_5 = {8a cb 6a 01 f6 d9 1b c9 6a 00 81 e1 6b 01 00 00 6a 03 6a 00 83 c1 50 6a 00 51 52 50 ff 15 ?? ?? ?? ?? 8b f0 85 f6 89 74 24 14 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_S_164430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!S"
        threat_id = "164430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 52 65 70 65 61 74 [0-4] 64 65 6c 20 22 25 73 22 [0-4] 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 [0-4] 64 65 6c 20 22 25 73 22}  //weight: 1, accuracy: Low
        $x_2_2 = {68 69 64 64 65 6e 00 [0-17] 6f 6e 63 68 61 6e 67 65 00 [0-4] 6f 6e 6b 65 79 70 72 65 73 73 00 [0-4] 6f 6e 6b 65 79 75 70 00 [0-4] 6f 6e 6b 65 79 64 6f 77 6e 00}  //weight: 2, accuracy: Low
        $x_2_3 = {6b 6a 68 67 71 74 32 66 6a 31 67 64 68 33 2e 74 6d 70 00}  //weight: 2, accuracy: High
        $x_1_4 = "Use%sill%snd%sv:1.9.0.1) Gecko/200" ascii //weight: 1
        $x_2_5 = {59 59 ff d7 33 d2 8b cd f7 f1 52 ff d6 8d 44 24 48 50 8d 84 24 a4 02 00 00 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 84 24 24 01 00 00 68 ?? ?? ?? ?? 50 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Koobface_J_164441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.J"
        threat_id = "164441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 f6 b9 0f 00 00 00 56 49 75 fc 6a 20 8d 9d 44 ff ff ff 53 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {72 46 87 d9 2b d9 fc 51 c1 e9 02 f3 a5 59 83 e1 03 f3 a4 5e 8b cb 51 c1 e9 02 f3 a5 59 83 e1 03 f3 a4 8b bd 78 ff ff ff 8b f2 87 74 3d 98 e8}  //weight: 5, accuracy: High
        $x_1_3 = "chat/send.php" ascii //weight: 1
        $x_1_4 = "updatestatus.php" ascii //weight: 1
        $x_1_5 = "ufi/modify.php" ascii //weight: 1
        $x_1_6 = "&xhpc_message" ascii //weight: 1
        $x_1_7 = "&msg_text=" ascii //weight: 1
        $x_1_8 = "&to_offline=" ascii //weight: 1
        $x_1_9 = "&add_comment_text_text=" ascii //weight: 1
        $x_1_10 = "&mood=" ascii //weight: 1
        $x_1_11 = "SaveStatus.ashx" ascii //weight: 1
        $x_1_12 = "&e_format=" ascii //weight: 1
        $x_1_13 = "&e_message=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Koobface_T_167235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.gen!T"
        threat_id = "167235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#BLACKLABEL" ascii //weight: 1
        $x_1_2 = "blogger.com/" ascii //weight: 1
        $x_1_3 = "blogspot.com/" ascii //weight: 1
        $x_1_4 = "/AccountRecoveryOptionsPrompt" ascii //weight: 1
        $x_1_5 = "c:\\googleregjs.bat" ascii //weight: 1
        $x_1_6 = {3a 52 65 70 65 61 74 20 0a 20 64 65 6c 20 22 25 73 22 20 0a 20 69 66 20 65 78 69 73 74 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Koobface_K_167531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Koobface.K"
        threat_id = "167531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "#BLUELABEL" ascii //weight: 5
        $x_1_2 = "action=ldtor" ascii //weight: 1
        $x_1_3 = "gen&v=" ascii //weight: 1
        $x_1_4 = "&hardid=" ascii //weight: 1
        $x_1_5 = "KILL" ascii //weight: 1
        $x_1_6 = "/.sys.php" ascii //weight: 1
        $x_1_7 = "&totaldr=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

