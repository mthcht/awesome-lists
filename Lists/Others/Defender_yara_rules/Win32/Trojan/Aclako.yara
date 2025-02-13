rule Trojan_Win32_Aclako_A_2147658274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aclako.gen!A"
        threat_id = "2147658274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aclako"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 45 ff 46 88 07 47 4b 75 e6 0f b7 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f1 4d 5a 00 00 66 89 0f 8b 4f 3c}  //weight: 1, accuracy: High
        $x_1_3 = {80 3f 4d 0f 85 ?? ?? ?? ?? 80 7f 01 5a 0f 85 ?? ?? ?? ?? be 04 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Aclako_B_2147663913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aclako.B"
        threat_id = "2147663913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aclako"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 44 24 0f 46 88 07 47 4b 75 e6 0f b7 44 24 14}  //weight: 2, accuracy: High
        $x_2_2 = {66 31 44 24 14 8b 45 0c 66 39 44 24 14 76 05 66 89 44 24 14 33 c0 66 3b 44 24 14 73 25 8b 7d 08 8d 73 06 0f b7 5c 24 14}  //weight: 2, accuracy: High
        $x_2_3 = {51 ff 50 40 56 8d 84 24 99 05 00 00 53 50 88 9c 24 a0 05 00 00 e8}  //weight: 2, accuracy: High
        $x_1_4 = {25 73 25 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {3c 5f 44 61 74 61 4b 65 79 5f 5f 44 61 74 61 4b 65 79 5f 3e 00}  //weight: 1, accuracy: High
        $x_1_6 = {6d 6f 6f 6f 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_7 = {62 65 66 73 76 63 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {47 6c 6f 62 61 6c 5c 52 54 5f 4d 41 49 4e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

