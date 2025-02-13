rule TrojanClicker_Win32_Losicoa_A_2147685164_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Losicoa.A"
        threat_id = "2147685164"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Losicoa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 5a f8 0f 85 33 02 00 00 68 ?? 21 42 00 8d 4c 24 1c e8 8b de 00 00 8b 44 24 18 6a 05 53 50 68 34 21 42 00 68 2c 21 42 00 53 c6 44 24 50 03 ff 15 74 c2 41 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 18 01 00 00 00 83 f8 06 77 3f ff 24 85 30 46 40 00 68 ?? ?? 42 00 eb 28 68 ?? ?? 42 00 eb 21 68 ?? ?? 42 00 eb 1a 68 ?? ?? 42 00 eb 13 68 ?? ?? 42 00 eb 0c 68 ?? ?? 42 00 eb 05 68 ?? ?? 42 00 8d 4c 24 0c e8 4e da 00 00 6a 04 6a 01 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

