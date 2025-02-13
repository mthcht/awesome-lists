rule DDoS_Win32_Flusihoc_A_2147706946_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/Flusihoc.A"
        threat_id = "2147706946"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Flusihoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3c 7c 74 0f (3a|3c) ?? 74 0b ?? 88 01 8a 04 ?? 41 84 c0 75 ed}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 88 01 00 00 75 05 fe 06 fe 46 1e 3d 68 01 00 00 75 05 fe 06 fe 4e 17 83 f8 34 75 03 fe 4e 18}  //weight: 2, accuracy: High
        $x_2_3 = {83 c6 04 83 c4 0c 81 ?? 90 01 00 00 81 ?? 2c 01 00 00 81 fe ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
        $x_2_4 = {25 73 7c 25 73 7c 25 73 7c 25 73 7c 25 73 65 6e 64 00}  //weight: 2, accuracy: High
        $x_1_5 = {53 59 4e 5f 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {55 44 50 5f 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {49 43 4d 50 5f 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {54 43 50 5f 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {48 54 54 50 5f 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_10 = {44 4e 53 5f 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_11 = {43 4f 4e 5f 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_12 = {43 43 5f 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

