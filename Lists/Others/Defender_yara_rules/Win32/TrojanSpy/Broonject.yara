rule TrojanSpy_Win32_Broonject_B_2147652933_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Broonject.B"
        threat_id = "2147652933"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Broonject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c1 e9 02 f3 a5 8b c8 83 e1 03 8b c3 f3 a4 48 8d a4 24 00 00 00 00 8a 48 01 40 84 c9 75 ?? 66 8b 0d ?? ?? ?? ?? 6a 00 6a 00 6a 00 66 89 08 8a 15 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 88 50 02 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 83 f8 04 0f 84 ?? ?? ?? ?? 83 f8 01 74 ?? 83 f8 03 74 ?? 83 f8 02 75 ?? 83 fb 07 7d ?? 68 e8 03 00 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 61 72 6b 3a [0-16] 70 49 44 3a 25 64 [0-8] 64 6f 6d 61 69 6e 3a 25 73}  //weight: 1, accuracy: Low
        $x_1_4 = {67 6f 6f 6e [0-4] 52 65 61 64 20 65 72 72 6f 72 [0-4] 43 61 6e 27 74 20 77 72 69 74 65}  //weight: 1, accuracy: Low
        $x_1_5 = "puzzleofworld.com" ascii //weight: 1
        $x_1_6 = "freshjokes.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

