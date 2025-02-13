rule TrojanClicker_Win32_Worbe_2147598222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Worbe"
        threat_id = "2147598222"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Worbe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 55 10 83 c2 04 8b 02 85 c0 7c 06 32 45 0c 88 01 41 ff 4d 10 83 7d 10 00 7f e8 8b 09 00 5f 7e 21 8d 8d ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = {2f 73 63 72 69 70 74 73 2f 77 6f 72 6b 65 72 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 63 74 69 6f 6e 3d 67 65 74 25 35 46 73 63 72 69 70 74 26 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

