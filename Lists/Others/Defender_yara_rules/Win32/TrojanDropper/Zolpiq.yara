rule TrojanDropper_Win32_Zolpiq_A_2147645511_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zolpiq.A"
        threat_id = "2147645511"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zolpiq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 3a 8b 4f 04 8b 56 0c 3b ca 72 30 8b 46 10 03 c2 3b c8 73 27 8b 46 14 2b c2}  //weight: 1, accuracy: High
        $x_1_2 = {59 8b c1 83 c0 24 50 81 c1 00 00 00 00 3e 8b 01 05 00 00 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = {6d 73 74 64 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDropper_Win32_Zolpiq_C_2147646087_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Zolpiq.C"
        threat_id = "2147646087"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Zolpiq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 c2 7f 30 10 41 81 f9 00 40 9c 00 7c eb}  //weight: 1, accuracy: High
        $x_1_2 = {03 f8 8b 86 10 01 00 00 03 c3 2b b8 0c 01 00 00 05 08 01 00 00 2b be 0c 01 00 00 47 39 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

