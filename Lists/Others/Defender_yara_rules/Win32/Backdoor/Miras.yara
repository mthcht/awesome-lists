rule Backdoor_Win32_Miras_A_2147688805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Miras.A"
        threat_id = "2147688805"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Miras"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 8b 74 24 0c 33 c0 85 f6 7e 17 8a 54 24 10 8b 4c 24 08 53 8a 1c 08 32 da 88 1c 08 40 3b c6 7c f3 5b 5e c3}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 10 55 66 c7 44 24 11 e1 00 66 8b 44 24 10 8a 4c 24 12 66 89 02 c6 44 24 18 00 c6 44 24 19 00 c6 44 24 1a 00 88 4a 02 c7 44 24 1b 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 fe 68 01 00 00 0f 8c 83 00 00 00 c6 84 24 80 00 00 00 55 66 c7 84 24 81 00 00 00 07 00 66 8b 94 24 80 00 00 00 8a 84 24 82 00 00 00 88 5c 24 10 88 5c 24 11 88 5c 24 12 c7 44 24 13 71 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

