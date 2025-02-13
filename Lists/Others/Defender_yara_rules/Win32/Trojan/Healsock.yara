rule Trojan_Win32_Healsock_2147616264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Healsock"
        threat_id = "2147616264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Healsock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 69 6e 48 65 61 6c 65 72 2e 64 6c 6c 00 44 6c 6c 4d 61 69 6e}  //weight: 2, accuracy: High
        $x_2_2 = {70 61 73 73 20 00 00 00 75 73 65 72}  //weight: 2, accuracy: High
        $x_1_3 = "MS.w95.spi.tcp" ascii //weight: 1
        $x_1_4 = {00 57 53 50 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_5 = "/temp/settings/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Healsock_2147616264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Healsock"
        threat_id = "2147616264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Healsock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 53 4e 00 [0-4] 47 6f 6f 67 6c 65 00 [0-4] 41 70 70 6c 65 00 [0-4] 49 6e 74 65 6c 00 [0-4] 41 64 6f 62 65 00 [0-4] 4d 69 63 72 6f 73 6f 66 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {57 65 62 00 [0-4] 4e 65 74 77 6f 72 6b 00 [0-4] 57 69 6e 64 6f 77 73 00 [0-4] 53 79 73 74 65 6d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 6f 6e 69 74 6f 72 00 [0-4] 44 72 69 76 65 72 00 [0-4] 46 69 6c 74 65 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = {25 73 20 6f 76 65 72 20 5b 25 73 5d 00}  //weight: 1, accuracy: High
        $x_1_5 = {57 53 50 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {57 53 43 57 72 69 74 65 50 72 6f 76 69 64 65 72 4f 72 64 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

