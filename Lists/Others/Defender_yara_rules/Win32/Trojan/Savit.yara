rule Trojan_Win32_Savit_A_2147654039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Savit.A"
        threat_id = "2147654039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Savit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 69 73 74 61 44 4c 4c 50 72 6f 20 52 55 4e 4e 49 4e 47 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 73 32 68 65 6c 70 2e 50 4e 46 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 70 73 65 63 73 74 61 70 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 45 43 68 65 63 6b 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {2d 74 20 22 25 73 22 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 66 53 65 41 67 6e 74 2e 65 78 65 ?? ?? ?? ?? 50 63 53 63 6e 53 72 76 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Savit_B_2147657041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Savit.B"
        threat_id = "2147657041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Savit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 54 24 10 8b 4c 24 08 53 8a 1c 08 32 da 88 1c 08 40 3b c6 7c}  //weight: 2, accuracy: High
        $x_1_2 = {f2 ae f7 d1 2b f9 89 75 e0 8b c1 8b f7 8b 7d e0 89 55 ec c1 e9 02}  //weight: 1, accuracy: High
        $x_1_3 = "Want Wood To Exit" ascii //weight: 1
        $x_1_4 = "IPV4.bak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

