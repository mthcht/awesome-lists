rule Rogue_Win32_MajorDefenseKit_154070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/MajorDefenseKit"
        threat_id = "154070"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "MajorDefenseKit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Major Defense Kit" wide //weight: 1
        $x_1_2 = {74 00 68 00 65 00 20 00 6e 00 65 00 63 00 65 00 73 00 73 00 61 00 72 00 79 00 20 00 68 00 65 00 75 00 72 00 69 00 73 00 74 00 69 00 63 00 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 20 00 61 00 6e 00 64 00 20 00 70 00 65 00 72 00 66 00 6f 00 72 00 6d 00 20 00 61 00 20 00 66 00 75 00 6c 00 6c 00 20 00 73 00 63 00 61 00 6e 00 20 00 6f 00 66 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 74 00 6f 00 20 00 65 00 78 00 74 00 65 00 72 00 6d 00 69 00 6e 00 61 00 74 00 65 00 20 00 6d 00 61 00 6c 00 69 00 63 00 69 00 6f 00 75 00 73 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 20 00 66 00 72 00 6f 00 6d 00 20 00 69 00 74 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 21 00 20 00 52 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 74 00 72 00 69 00 61 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {20 00 66 00 69 00 6c 00 65 00 73 00 20 00 63 00 61 00 6e 00 27 00 74 00 20 00 62 00 65 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 65 00 64 00 20 00 28 00 68 00 65 00 75 00 72 00 69 00 73 00 74 00 69 00 63 00 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 20 00 6d 00 69 00 73 00 73 00 69 00 6e 00 67 00 29 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

