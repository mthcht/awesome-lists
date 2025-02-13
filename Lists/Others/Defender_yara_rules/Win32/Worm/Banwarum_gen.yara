rule Worm_Win32_Banwarum_gen_A_2147573757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Banwarum_gen!dr.A"
        threat_id = "2147573757"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Banwarum_gen"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "hlegehrivihbugPhSeDe" ascii //weight: 4
        $x_4_2 = "h.exehogonhwinl" ascii //weight: 4
        $x_4_3 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e 00 57 69 6e 33 32 2e 5a}  //weight: 4, accuracy: High
        $x_2_4 = {74 5b 50 6a 00 68 ff 0f 1f 00 ff 15}  //weight: 2, accuracy: High
        $x_2_5 = {74 49 89 c7 6a 40 68 00 30 00 00 68 00 01 00 00 6a 00 57 ff 15}  //weight: 2, accuracy: High
        $x_1_6 = {00 00 50 00 02 00 00 00 04 00 0f 00 ff ff 00 00 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Banwarum_gen_A_2147573758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Banwarum_gen!dll.A"
        threat_id = "2147573758"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Banwarum_gen"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "Worm.Win32.Zasrancheg" ascii //weight: 4
        $x_4_2 = {00 2e 67 69 66 20 20 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 4, accuracy: Low
        $x_3_3 = {00 6c 73 61 73 73 2e 65 78 65 ?? ?? ?? 44 6c 6c 4e 61 6d 65 00 53 74 61 72 74 75 70 00 41 73 79 6e 63}  //weight: 3, accuracy: Low
        $x_3_4 = {83 f8 ff 74 1b 85 c0 74 17 46 43 8b 45 f8 50 8b 45 f4 50}  //weight: 3, accuracy: High
        $x_2_5 = "wave-flash, application/vnd.ms-excel" ascii //weight: 2
        $x_2_6 = {63 6f 6e 74 61 63 74 00 70 72 69 76 61 63 79 00 73 65 72 76 69 63 65 00 61 62 75 73 65}  //weight: 2, accuracy: High
        $x_2_7 = {2e 6f 72 67 00 62 73 64 2e 69 74}  //weight: 2, accuracy: High
        $x_2_8 = "bei der Postbank" ascii //weight: 2
        $x_2_9 = {0d 0a 4d 65 69 6e 65 20 4b 6f 6e 74 6f 6e 75 6d 6d 65 72}  //weight: 2, accuracy: High
        $x_2_10 = {0f b7 45 f0 6b c0 3c 66 03 45 f2 6b c0 3c 31 d2 66 8b 55 f4 01 d0 69 c0 e8 03 00 00 66}  //weight: 2, accuracy: High
        $x_2_11 = {50 83 7d 0c 01 1b c0 40 83 e0 7f 50 8b 45 08 50}  //weight: 2, accuracy: High
        $x_2_12 = "Server: Apache/2.0.52 (Win32)" ascii //weight: 2
        $x_1_13 = {6a 04 8d 45 f8 50 68 06 10 00 00 68 ff ff 00 00 53 e8}  //weight: 1, accuracy: High
        $x_1_14 = {6a 04 8d 45 f8 50 68 05 10 00 00 68 ff ff 00 00 53 e8}  //weight: 1, accuracy: High
        $x_1_15 = {41 00 b2 02 b0 02 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_2_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

