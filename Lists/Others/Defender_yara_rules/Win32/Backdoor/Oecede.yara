rule Backdoor_Win32_Oecede_A_2147603219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Oecede.A"
        threat_id = "2147603219"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Oecede"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {85 c9 74 0d 33 db 8a 1a 32 d8 88 1a 42 d1 c8 e2 f5 5a 59 5b c9 c2 08 00}  //weight: 2, accuracy: High
        $x_2_2 = {e9 da 00 00 00 81 fb 07 00 02 00 74 5b 81 fb 03 00 01 00 74 14 81 fb 07 00 03 00 0f 85}  //weight: 2, accuracy: High
        $x_1_3 = {5c 6b 62 64 2e 73 79 73 00 00 00 5c 5c 2e 5c 6b 62 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 3f 3f 5c 25 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

