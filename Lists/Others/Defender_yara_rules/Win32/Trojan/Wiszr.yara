rule Trojan_Win32_Wiszr_A_2147684725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wiszr.A"
        threat_id = "2147684725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wiszr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 69 73 77 69 7a 61 72 64 2e 37 7a 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 72 6f 63 65 78 70 2e 65 78 65 [0-4] 74 61 73 6b 6d 67 72 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {00 6d 69 6e 65 72 20 55 49 44 00}  //weight: 1, accuracy: High
        $x_1_4 = "dwm.exe -pool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wiszr_B_2147685590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wiszr.B"
        threat_id = "2147685590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wiszr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 72 75 6e 6d 65 00 73 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 69 73 77 69 7a 61 72 64 2e 37 7a 00}  //weight: 1, accuracy: High
        $x_1_3 = "indexer.exe -poolip=" ascii //weight: 1
        $x_1_4 = "cidaemon.exe -c proxy.conf" ascii //weight: 1
        $x_1_5 = "dwm.exe -poolip=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wiszr_C_2147686403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wiszr.C"
        threat_id = "2147686403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wiszr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "yoZEdHXuKvcgbqoHalesQMtDoRftOzbkNiwEMHhomP" ascii //weight: 10
        $x_2_2 = {2e 64 6c 6c 00 72 75 6e 6d 65}  //weight: 2, accuracy: High
        $x_4_3 = {c1 e8 0b 0f af 45 b4 89 45 ac 8b 4d ec 3b 4d ac 73 30 [0-8] b8 00 08 00 00}  //weight: 4, accuracy: Low
        $x_2_4 = {8b 4d 10 03 4d f8 0f b6 11 33 c2 8b 4d 18 03 4d fc 88 01 eb ac}  //weight: 2, accuracy: High
        $x_2_5 = {83 c4 18 8d 55 fc 52 68 74 9a 04 00 8b 45 f8 50 e8}  //weight: 2, accuracy: High
        $x_2_6 = {73 23 8b 4d c8 c1 e1 08 89 4d c8 8b 55 ec c1 e2 08 8b 45 d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

