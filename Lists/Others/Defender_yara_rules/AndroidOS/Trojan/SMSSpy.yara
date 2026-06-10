rule Trojan_AndroidOS_SMSSpy_K_2147971276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SMSSpy.K!MSR"
        threat_id = "2147971276"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SMSSpy"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {22 0e 42 00 22 0e 42 00 70 10 76 00 0e 00 22 0f 3d 00 70 10 6c 00 0f 00 08 10 00 00 1a 00 dd 00 6e 20 6f 00 0f 00 0c 00 6e 20 6f 00 70 00 0c 00 1a 0f a8 00 6e 20 6f 00 f0 00 0c 00 6e 20 6f 00 a0 00 0c 00 1a 0f a6 00 6e 20 6f 00 f0 00 0c 00 62 0f 0a 00 6e 20 6f 00 f0 00 0c 0d}  //weight: 1, accuracy: High
        $x_1_2 = {21 57 35 76 c7 00 46 07 04 06 1f 07 48 00 71 10 16 00 07 00 0c 07 4d 07 05 06 46 07 05 06 6e 10 18 00 07 00 0c 07 46 08 05 06 6e 10 17 00 08 00 0c 08 1a 09 13 00 1a 0a 0e 00 6e 30 69 00 98 0a 0c 09 1a 0a 11 00 6e 30 69 00 a9 00 0c 0a 1a 0b 1a 00 6e 30 69 00 ba 00 0c 0b 1a 0c 16 00 07 8d}  //weight: 1, accuracy: High
        $x_1_3 = {22 00 3d 00 70 10 6c 00 00 00 1a 01 7f 00 6e 20 6f 00 10 00 0c 00 71 00 71 00 00 00 0c 01 6e 10 72 00 01 00 0b 01 6e 30 6d 00 10 02 0c 00 6e 10 70 00 00 00 0c 00 1a 01 c1 00 71 20 1a 00 01 00 6e 10 7a 00 05 00 0a 00 38 00 09 00 6e 10 79 00 05 00 0c 00 6e 10 7b 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

