rule Backdoor_Win32_Doubickit_A_2147679531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Doubickit.A"
        threat_id = "2147679531"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Doubickit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 73 73 2e 65 78 65 20 61 64 2e 64 6f 75 62 6c 63 69 6c 63 6b 2e 6e 65 74 20 39 30 30 30 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 77 62 65 6d 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 8d 85 bc ca ff ff 50 e8 ?? ?? ?? ?? 83 c4 08 c7 85 bc cb ff ff 51 00 00 00 8d 55 d4 52 6a 00 8d 8d a4 c9 ff ff 51 68 fc 14 40 00 6a 00 6a 00 e8 ?? ?? ?? ?? ff 75 ec e8}  //weight: 1, accuracy: Low
        $x_1_4 = {83 b8 24 36 00 00 00 74 7b 8d 55 c8 52 6a 00 6a 02 8b 4d fc ff b1 2c 36 00 00 8b 45 fc ff b0 28 36 00 00 8b 55 fc ff b2 24 36 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

