rule Trojan_Win32_Busky_A_98826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Busky.gen!A"
        threat_id = "98826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Busky"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "URLDownloadToCacheFileA" ascii //weight: 10
        $x_5_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
        $x_3_3 = "SOFTWARE\\AdwareDisableKey4" ascii //weight: 3
        $x_3_4 = "SOFTWARE\\AdwareDisableKey3" ascii //weight: 3
        $x_3_5 = "http://207.226.177.108/sc.exe" ascii //weight: 3
        $x_3_6 = "http://www.zabosaltd.biz/wafugi?id=COMPIDHERE&w=WEBMIDHERE&step=" ascii //weight: 3
        $x_4_7 = {fe ff ff 68 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 74 c6 85 ?? ?? ff ff 70 c6 85 ?? ?? ff ff 3a c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 36}  //weight: 4, accuracy: Low
        $x_4_8 = {fe ff ff 2e c6 85 ?? ?? ff ff 31 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 37 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 31 c6 85 ?? ?? ff ff 30 c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 45 c6 85 ?? ?? ff ff 49 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 51 c6 85 ?? ?? ff ff 67}  //weight: 4, accuracy: Low
        $x_4_9 = {fe ff ff 61 c6 85 ?? ?? ff ff 48 c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 32 c6 85 ?? ?? ff ff 36 c6 85 ?? ?? ff ff 62 c6 85 ?? ?? ff ff 59 c6 85 ?? ?? ff ff 47 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 65 c6 85 ?? ?? ff ff 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_4_*) and 3 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Busky_D_121166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Busky.D"
        threat_id = "121166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Busky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 fc 00 00 00 00 e9}  //weight: 10, accuracy: High
        $x_10_2 = {81 7d fc 80 00 00 00 0f 8d}  //weight: 10, accuracy: High
        $x_1_3 = {6f 75 74 2e 64 6c 6c 00 [0-5] 49 6e 69 74 00 50 72 6f 63}  //weight: 1, accuracy: Low
        $x_1_4 = "Sv6MVaV19D" ascii //weight: 1
        $x_1_5 = {2f 64 6f 77 6e 6c 6f 61 64 [0-1] 2e 70 68 70 3f 61 66 66 69 64 3d [0-15] 26 73 75 62 61 63 63 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Busky_EE_121684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Busky.EE"
        threat_id = "121684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Busky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "310"
        strings_accuracy = "Low"
    strings:
        $x_300_1 = {40 00 c3 c7 45 03 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 81 03 01 01 01 75 45 6d}  //weight: 300, accuracy: Low
        $x_10_2 = "http://88.208.17.127/" ascii //weight: 10
        $x_10_3 = "http://58.65.239.124/" ascii //weight: 10
        $x_10_4 = "http://63.219.176.248/" ascii //weight: 10
        $x_10_5 = "http://63.219.178.162/" ascii //weight: 10
        $x_10_6 = "http://205.252.24.246/" ascii //weight: 10
        $x_10_7 = "http://205.177.124.74/" ascii //weight: 10
        $x_10_8 = "http://207.226.171.35/" ascii //weight: 10
        $x_10_9 = "http://207.226.171.36/" ascii //weight: 10
        $x_10_10 = "http://209.62.108.220/" ascii //weight: 10
        $x_10_11 = "http://209.62.108.213/" ascii //weight: 10
        $x_10_12 = "http://getyouneed.com" ascii //weight: 10
        $x_10_13 = "/c del C:\\myapp.exe >> NUL" ascii //weight: 10
        $x_10_14 = "/c del /f C:\\myapp.exe.bak >> NUL" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_300_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Busky_EF_121743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Busky.EF"
        threat_id = "121743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Busky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 89 45 b1 c6 45 ?? 68 c6 45 ?? 74 c6 45 ?? 74 c6 45 ?? 70 c6 45 ?? 3a c6 45 ?? 2f c6 45 ?? 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 e8 83 c6 01 80 3e 45 74 02 eb 0b 8b 75 e8 83 c6 02 80 3e 42 74 02 eb 0b 8b 75 e8 83 c6 03 80 3e 4d 74 02 eb 0b 8b 75 e8 83 c6 04 80 3e 49 74 02 eb 0b 8b 75 e8}  //weight: 1, accuracy: High
        $x_1_3 = {c1 6d dc 0a 8b 45 dc 31 45 e8 8b 45 e8 89 45 d8 c1 65 d8 03 8b 45 d8 01 45 e8 8b 45 e8 89 45 d4 c1 6d d4 06 8b 45 d4 31 45 e8 8b 45 e8 89 45 d0 c1 65 d0 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Busky_I_122081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Busky.I"
        threat_id = "122081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Busky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 94 14 00 00 90 13 [0-17] e8 ?? ?? ?? ?? 68 ?? ?? ?? 00 68 ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {00 87 04 75 1f ef d0 11 98 88 00 60 97 de ac f9}  //weight: 1, accuracy: High
        $x_1_3 = {61 56 31 39 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Busky_J_122275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Busky.J"
        threat_id = "122275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Busky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 94 14 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 87 04 75 1f ef d0 11 98 88 00 60 97 de ac f9}  //weight: 1, accuracy: High
        $x_1_3 = {81 7d fc 80 00 00 00 0f 8d}  //weight: 1, accuracy: High
        $x_1_4 = {61 56 31 39 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

