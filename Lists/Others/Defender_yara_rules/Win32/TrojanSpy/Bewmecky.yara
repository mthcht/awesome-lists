rule TrojanSpy_Win32_Bewmecky_A_2147626861_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bewmecky.A"
        threat_id = "2147626861"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bewmecky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 f9 40 74 04 3b ef 7c f3 33 f6 33 ff 85 ed 0f 8e ?? ?? 00 00 80 3c 38 23 0f 85 ?? ?? 00 00 83 fb 01 75 1b}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 1f 80 3c 32 5c 74 07 4a 3b d3 7f f5 eb 12}  //weight: 1, accuracy: High
        $x_1_3 = {83 e8 05 8d 48 a4 83 f9 04 77 03 83 c0 1a 8d 48 c4 83 f9 04 77 03 83 c0 1a 8d 48 d5 83 f9 04 77 03 83 c0 0a ff 45 fc 88 04 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

