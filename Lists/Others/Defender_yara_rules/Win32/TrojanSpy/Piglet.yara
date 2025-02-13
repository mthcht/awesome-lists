rule TrojanSpy_Win32_Piglet_A_2147729831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Piglet.A!bit"
        threat_id = "2147729831"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Piglet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 15 18 00 00 00 8b 52 30 8b 52 08 3b 55 0c 74 11 8b 75 10 89 f7 8b 4d 14 ad 2b 45 0c 01 d0 ab e2 f7}  //weight: 1, accuracy: High
        $x_1_2 = {74 76 5f 77 c7 45 ?? 33 32 2e 64 66 c7 45 ?? 6c 6c c6 45 f3 00 c7 45 f4 75 63 35 38 c7 45 f8 67 74 6b 2e 66 c7 45 fc 63 66 c6 45 fe 67 c6 45 ff 00}  //weight: 1, accuracy: Low
        $x_1_3 = {fe c3 8a 14 1f 00 d0 8a 0c 07 88 0c 1f 88 14 07 00 d1 8a 0c 0f 30 0e 46 ff 4d 10 75 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

