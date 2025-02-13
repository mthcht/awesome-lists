rule TrojanProxy_Win32_Koobface_H_2147803962_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!H"
        threat_id = "2147803962"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 53 c6 45 ?? 31 c6 45 ?? 32 c6 45 ?? 37 c6 45 ?? 2e}  //weight: 2, accuracy: Low
        $x_2_2 = {68 95 1f 00 00 aa e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = {4f 4f f7 df 1b ff 83 e7 0a 69 ff e8 03 00 00 59 57 ff 15 ?? ?? 40 00 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_4 = "adD \"hkLm\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_I_2147803963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!I"
        threat_id = "2147803963"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "post=true&path=captcha&a=query&b=%s&id=%s" ascii //weight: 1
        $x_1_2 = "?action=bs&v=20&a=names" ascii //weight: 1
        $x_1_3 = "http://news.google.com/news?ned=us&output=rss" ascii //weight: 1
        $x_1_4 = "accounts/Captcha" ascii //weight: 1
        $x_1_5 = "#BLACKLABEL" ascii //weight: 1
        $x_1_6 = {85 c0 7e 28 01 44 ?? ?? 83 bc 24 14 ?? ?? ?? ?? 74 0d 8b 8c 24 ?? ?? ?? ?? 85 c9 74 02 01 01 6a 00 68 00 04 00 00 ff 74 ?? ?? eb cb}  //weight: 1, accuracy: Low
        $x_2_7 = {74 16 8a 08 80 f9 30 74 3a 80 f9 31 74 0a 80 f9 32 74 30 80 f9 33 74 0f}  //weight: 2, accuracy: High
        $x_2_8 = {6a 7c 50 c6 ?? ?? ?? ff 15 ?? ?? ?? ?? 59 85 c0 59}  //weight: 2, accuracy: Low
        $x_1_9 = {40 00 33 c0 83 ?? ?? ?? 0f 95 c0 48 83 e0 ?? 83 c0 ?? 69 c0 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_A_2147803994_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!A"
        threat_id = "2147803994"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "process-domain" ascii //weight: 3
        $x_3_2 = {70 72 6f 25 73 61 69 6e 00 00 00 00 63 65 73 73}  //weight: 3, accuracy: High
        $x_3_3 = {25 73 6f 25 73 61 69 6e 00 00 00 00 70 72 00}  //weight: 3, accuracy: High
        $x_3_4 = "process-clicks" ascii //weight: 3
        $x_2_5 = "/search.php?p=%04d" ascii //weight: 2
        $x_2_6 = "CU-%d:" ascii //weight: 2
        $x_2_7 = "IGYMAS" ascii //weight: 2
        $x_1_8 = "user_pref(\"network.proxy.http_port" ascii //weight: 1
        $x_1_9 = {65 72 76 65 72 00 68 74 74 70 3d 31 32 37 2e 30}  //weight: 1, accuracy: High
        $x_4_10 = {6a 04 eb c1 56 68 ?? ?? ?? ?? 57 e8 ?? ?? ff ff f6 d8}  //weight: 4, accuracy: Low
        $x_2_11 = {6a 1e 51 68 98 01 22 00}  //weight: 2, accuracy: High
        $x_2_12 = {68 9e 1b 00 00}  //weight: 2, accuracy: High
        $x_1_13 = {c6 45 08 55 c6 45 09 0d}  //weight: 1, accuracy: High
        $x_1_14 = {c6 45 fc d5 c6 45 fd ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_B_2147803998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!B"
        threat_id = "2147803998"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 03 1c 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 02 55 55 6a 1a 68 ff ff 00 00 50 8d 44 24 ?? 50 e8 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 08 55 c6 45 09 0d}  //weight: 1, accuracy: High
        $x_1_4 = "p%ses%slic%s" ascii //weight: 1
        $x_1_5 = "IGYMAS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanProxy_Win32_Koobface_C_2147803999_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!C"
        threat_id = "2147803999"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7c f2 83 c5 04 88 14 ?? 8b c5 39 55 00 75 ?? 5f}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 1a 68 ff ff 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
        $x_1_3 = {68 03 1c 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 08 55 c6 45 09 0d}  //weight: 1, accuracy: High
        $x_1_5 = {83 c6 04 83 ff 06 59 8b d8 72 e0 85 db 74}  //weight: 1, accuracy: High
        $x_1_6 = {2e 75 13 6a 04 68}  //weight: 1, accuracy: High
        $x_1_7 = {6a 1e 50 68 ?? ?? 22 00 53 ff d7}  //weight: 1, accuracy: Low
        $x_1_8 = "IAMGSY" ascii //weight: 1
        $x_3_9 = {83 c0 05 50 e8 ?? ?? 00 00 8b ?? 59 83 ?? 03 0f 85 ?? ?? 00 00 8d 85 80 f8 ff ff}  //weight: 3, accuracy: Low
        $x_1_10 = {59 75 0f 47 83 c6 32 3b 7c 24 14 7c e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_F_2147804001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!F"
        threat_id = "2147804001"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 1e 50 68 ?? ?? 22 00 53 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 fc 55 c6 45 fd 0d}  //weight: 1, accuracy: High
        $x_1_3 = {59 75 12 46 83 c7 32 3b 74 24 10 7c e8}  //weight: 1, accuracy: High
        $x_1_4 = {73 66 78 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Koobface_G_2147804002_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!G"
        threat_id = "2147804002"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 25 c6 45 ?? 55 c6 45 ?? 0d c6 45 ?? ec}  //weight: 1, accuracy: Low
        $x_1_2 = {59 75 0f 46 83 c7 32 3b 74 24 10 7c e6}  //weight: 1, accuracy: High
        $x_1_3 = {00 50 4e 50 5f 54 44 49 00 7a 6f 6e 65 6c 6f 67 00 7a 6f 6e 65 6c 61 62 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Koobface_J_2147804006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!J"
        threat_id = "2147804006"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 0a 32 44 24 1c 88 01 49 4d 75 f3}  //weight: 2, accuracy: High
        $x_2_2 = "erokosvc.dll" ascii //weight: 2
        $x_1_3 = "/url?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_K_2147804008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!K"
        threat_id = "2147804008"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 29 32 54 24 14 88 11 49 48 75 f3}  //weight: 2, accuracy: High
        $x_2_2 = {6f 6b 6f 2e 64 6c 6c 04 00 (62 74|63 6c)}  //weight: 2, accuracy: Low
        $x_1_3 = "/url?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_L_2147804010_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!L"
        threat_id = "2147804010"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 29 32 44 24 1c 88 01 49 4f 75 f3}  //weight: 2, accuracy: High
        $x_2_2 = "certoko.dll" ascii //weight: 2
        $x_1_3 = "/url?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_M_2147804011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!M"
        threat_id = "2147804011"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 0f 32 54 24 1c 88 11 49 48 75 f3}  //weight: 2, accuracy: High
        $x_2_2 = {6f 6b 6f 2e 64 6c 6c 04 00 (6d 6d|62 74)}  //weight: 2, accuracy: Low
        $x_1_3 = "/url?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_N_2147804012_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!N"
        threat_id = "2147804012"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 29 32 54 24 20 88 11 49 48 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = "cfgormd.dll" ascii //weight: 1
        $x_1_3 = {6a 04 58 39 45 08 a3 ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Koobface_O_2147804013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!O"
        threat_id = "2147804013"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 0a 32 45 10 88 01 49 ff 4d 08 75 f2}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 29 32 54 24 18 88 11 49 48 75 f3}  //weight: 1, accuracy: High
        $x_1_3 = {8a 04 0f 32 45 0c 88 01 49 ff 4d fc 75 f2}  //weight: 1, accuracy: High
        $x_1_4 = "btw_oko.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Koobface_P_2147804017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!P"
        threat_id = "2147804017"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 fc 55 c6 45 fd 0d}  //weight: 1, accuracy: High
        $x_1_2 = {75 0f 47 83 c6 32 3b 7c 24 (10|14) 7c e5}  //weight: 1, accuracy: Low
        $x_1_3 = {50 44 52 56 2e 64 6c 6c 00 (53 65 72 76 69 63 65 4d 61 69|3f 6e 66 5f 61 64 64 52 75)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanProxy_Win32_Koobface_D_2147804025_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!D"
        threat_id = "2147804025"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 10
        $x_10_2 = "me'+'th'+'od=\"P'+'oS'+'T'" ascii //weight: 10
        $x_10_3 = "GE%s50/%s=%d&s=%c&uid=%ld&p=%d&ip=%s&q=%s" ascii //weight: 10
        $x_1_4 = "sa.aol.com" ascii //weight: 1
        $x_1_5 = "yahooapis.com" ascii //weight: 1
        $x_1_6 = "metacafe.com" ascii //weight: 1
        $x_1_7 = "yimg.com" ascii //weight: 1
        $x_1_8 = "img.youtube.com" ascii //weight: 1
        $x_1_9 = "sugg.search" ascii //weight: 1
        $x_1_10 = "search.mdn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Koobface_E_2147804041_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!E"
        threat_id = "2147804041"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 5c 2e 5c 44 72 69 76 65 72 00 00 48 25 73 50 25 73 2e 25 64 20 25 64 32 25 73 76 65 25 73}  //weight: 1, accuracy: High
        $x_1_2 = "%s=%d&s=%c&uid=%ld&p=%d&ip=%s" ascii //weight: 1
        $x_1_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 64 72 69 76 65 72 00 00 00 00 53 74 61 72 74}  //weight: 1, accuracy: High
        $x_1_4 = {73 65 61 72 63 68 66 6f 72 3d 00 00 3f 71 75 65 72 79 3d 00 26 71 75 65 72 79 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanProxy_Win32_Koobface_Q_2147804140_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Koobface.gen!Q"
        threat_id = "2147804140"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Koobface"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 29 c6 45 fc 55 c6 45 fd 0d}  //weight: 1, accuracy: High
        $x_1_2 = {75 11 ff 15 ?? ?? ?? ?? 3d e5 03 00 00 0f 85 ?? ?? ?? ?? 68 ff 00 00 00 68 30 75 00 00 8d 45 ?? 53 50 6a 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

