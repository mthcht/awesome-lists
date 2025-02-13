rule Trojan_Win32_Cefyns_A_2147610826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cefyns.gen!A"
        threat_id = "2147610826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cefyns"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 4c 06 20 32 0c 30 32 4c 06 10 88 0c 30 40 83 f8 10 7c ec}  //weight: 2, accuracy: High
        $x_2_2 = {83 e8 05 a3 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 06 a1 ?? ?? ?? ?? 89 46 01 5e e9}  //weight: 2, accuracy: Low
        $x_2_3 = {67 65 74 5f 75 70 64 61 74 65 [0-1] 2e 70 68 70 3f 75 69 64 3d 25 73 26 76 3d 25 69}  //weight: 2, accuracy: Low
        $x_1_4 = {61 6c 74 63 6d 64 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 70 61 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_2_6 = {6a 64 25 ff ff 02 00 33 d2 59 f7 f1 8b 4d fc 8d 84 01 00 00 fd ff}  //weight: 2, accuracy: High
        $x_1_7 = {81 e9 47 86 c8 61 89 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cefyns_B_2147612431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cefyns.B"
        threat_id = "2147612431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cefyns"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c6 06 2f 46 c6 06 3f 46 c6 06 6b 46 c6 06 65}  //weight: 2, accuracy: High
        $x_2_2 = {c6 06 2f 46 c6 06 77 46 c6 06 77 46 c6 06 77}  //weight: 2, accuracy: High
        $x_2_3 = {2e c6 44 24 ?? 65 c6 44 24 ?? 78}  //weight: 2, accuracy: Low
        $x_2_4 = {67 65 74 5f 75 70 64 61 74 65 [0-1] 2e 70 68 70 3f 75 69 64 3d}  //weight: 2, accuracy: Low
        $x_2_5 = "?keyword=%s&Go=Go" ascii //weight: 2
        $x_1_6 = "lntop" ascii //weight: 1
        $x_1_7 = {00 61 6c 74 63 6d 64 33 32}  //weight: 1, accuracy: High
        $x_1_8 = "&lid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

