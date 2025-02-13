rule TrojanSpy_Win32_Talqou_A_2147648600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Talqou.A"
        threat_id = "2147648600"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Talqou"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 12 0f b6 11 33 c2 69 c0 ?? ?? 00 01 41 ff 4c 24 04 75 ee c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 fc 50 ff 75 fc 2b fe 6a 05 83 ef 05 56 c6 06 e9 89 7e 01 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 0c 8d 1c c1 8b 4d 08 8b 3c c1 8b 74 c1 04 0f cf 0f ce c7 45 fc ?? ?? ?? ?? c7 45 f4 20 00 00 00 ff 75 10 ff 75 fc 57 6a 0b 59 e8 d6 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ec 8c 00 00 00 83 4d fc ff ?? 8b 5e 3c ?? 8b 7c 33 78 03 fe 8b 47 20 8b 4f 18 03 c6 89 45 f4 89 4d f8 85 c9 75 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

