rule Trojan_Win32_Adept_A_2147617944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adept.A"
        threat_id = "2147617944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "wuauserv" ascii //weight: 10
        $x_10_2 = "\\system%d.exe" ascii //weight: 10
        $x_10_3 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c [0-8] 2e 61 78}  //weight: 10, accuracy: Low
        $x_10_4 = "WriteProcessMemory" ascii //weight: 10
        $x_10_5 = "InternetReadFile" ascii //weight: 10
        $x_1_6 = "AU service" ascii //weight: 1
        $x_1_7 = "INJECT is needed" ascii //weight: 1
        $x_1_8 = "Automatic updates service" ascii //weight: 1
        $x_1_9 = "Explorer.exe has been found" ascii //weight: 1
        $x_1_10 = "Signature of downloaded file is CORRECT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Adept_B_2147617972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adept.B"
        threat_id = "2147617972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 83 7d 0c 00 7c 05 4a 78 1a eb 11 8a 04 31 0a c0 74 04 3c ?? 75 06 80 34 31 ?? eb 07 80 34 31 ?? 41 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 5d 0c 8b 75 08 8a 0e d3 c1 83 c2 90 01 01 33 ca 33 c1 46 4b 75}  //weight: 1, accuracy: High
        $x_1_3 = {8b 43 3c 66 81 3c 18 50 45 0f 85 a2 00 00 00 8b 4c 18 78 0b c9 0f 84 96 00 00 00 83 7d 10 00 0f 84 8c 00 00 00 03 cb 8b 51 18}  //weight: 1, accuracy: High
        $x_1_4 = {33 d2 b9 30 00 00 00 64 ff 34 11 58 85 c0 78 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Adept_C_2147621458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adept.C"
        threat_id = "2147621458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {50 78 2e 41 78 00}  //weight: 3, accuracy: High
        $x_2_2 = {0f b6 d0 33 da 8b 45 0c 8b 08 8b 55 fc 88 1c 11 eb c8}  //weight: 2, accuracy: High
        $x_1_3 = {6a 02 6a 00 6a fb}  //weight: 1, accuracy: High
        $x_2_4 = {eb d1 8b 45 08 03 45 fc 0f b6 08 8b 45 fc 99 f7 7d 14 8b 45 10 0f b6 14 10 33 ca 8b 45 08 03 45 fc 88 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

