rule Trojan_Win32_Vxidl_C_2147595639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vxidl.gen!C"
        threat_id = "2147595639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vxidl"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e 3c bf 01 00 00 00 8d 45 ec 8b 55 fc 8a 54 3a ff 8b 4d f8 32 54 19 ff e8}  //weight: 4, accuracy: High
        $x_4_2 = "lkreme345" ascii //weight: 4
        $x_2_3 = {ff ff 50 6a 00 6a 00 68 25 80 00 00 6a 00 e8}  //weight: 2, accuracy: High
        $x_2_4 = {40 00 8b c0 53 33 db 6a 00 e8 ?? ?? ff ff 83 f8 07 75}  //weight: 2, accuracy: Low
        $x_2_5 = {8b 55 f0 8d 45 f4 e8 ?? ?? ff ff 6a 00 68 80 00 00 00 6a 04 6a 00 6a 00 68 00 00 00 40 8b 45 fc}  //weight: 2, accuracy: Low
        $x_2_6 = {23 31 00 00 23 32 00 00 53 4f 46 54 57 41 52 45}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vxidl_D_2147595640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vxidl.gen!D"
        threat_id = "2147595640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vxidl"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 ff ff 75 04 31 c0 eb ?? 6a 02 6a 00 6a 00 57 e8 [0-6] 6a 00 [0-10] 8d 45 fc 50 ff 75 10 ff 75 0c 57}  //weight: 4, accuracy: Low
        $x_3_2 = {00 75 0c c7 45 fc ?? 00 00 00 e9 ?? 00 00 00 6a 00 6a 00 6a 00 6a 00}  //weight: 3, accuracy: Low
        $x_4_3 = {6e 66 2f 63 6a 7b 00}  //weight: 4, accuracy: High
        $x_2_4 = {40 00 00 75 10 68 e0 93 04 00 e8}  //weight: 2, accuracy: High
        $x_2_5 = {6a 00 68 5e 01 00 00 68 c2 01 00 00 68 00 00 00 80 68 00 00 00 80 68 00 00 cf 00}  //weight: 2, accuracy: High
        $x_2_6 = {31 c0 40 eb 00 ff 75 cc 56 ff 75 f4 e8}  //weight: 2, accuracy: High
        $x_2_7 = {2f 63 6a 7b 00 25 73 5c}  //weight: 2, accuracy: High
        $x_1_8 = {68 00 7f 00 00 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_9 = "%s\\1213.4516" ascii //weight: 1
        $x_1_10 = "http://85." ascii //weight: 1
        $x_1_11 = "http://65." ascii //weight: 1
        $x_1_12 = {76 66 66 67 00}  //weight: 1, accuracy: High
        $x_1_13 = {2e 65 78 65 00 4d 65 78 69 6b 6f}  //weight: 1, accuracy: High
        $x_1_14 = {2e 65 78 65 00 49 74 61 6c}  //weight: 1, accuracy: High
        $x_1_15 = "%s\\vx" ascii //weight: 1
        $x_1_16 = "game1" ascii //weight: 1
        $x_1_17 = "tool1" ascii //weight: 1
        $x_1_18 = "vx.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((2 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

