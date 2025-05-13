rule Worm_Win32_Mofei_P_2147667654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mofei.P"
        threat_id = "2147667654"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {80 f1 55 88 4c 05 ?? 40 83 f8 18 72 ed 8d 45 ?? 88 5d}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 06 83 c4 0c 48 74 09 8a 4c 38 ff 30 0c 38 eb f4 80 37}  //weight: 5, accuracy: High
        $x_1_3 = {46 52 57 4b 5f 45 56 45 4e 54 5f 53 46 43 54 4c 43 4f 4d 5f 45 58 49 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {36 39 35 33 45 41 36 30 2d 38 44 35 46 2d 34 35 32 39 2d 38 37 31 30 2d 34 32 46 38 45 44 33 45 38 43 44 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 61 76 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {76 63 6b 62 70 61 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {77 6d 63 73 65 72 76 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {24 73 5c 73 79 73 74 65 6d 33 32 5c 26 73 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Mofei_ENAW_2147941300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mofei.ENAW!MTB"
        threat_id = "2147941300"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a da fe c3 32 19 88 18 40 41 42 3b 54 24 10}  //weight: 3, accuracy: High
        $x_3_2 = {8a 45 f4 83 c4 0c 88 04 1e 8a 45 f5 46 88 04 1e 46}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

