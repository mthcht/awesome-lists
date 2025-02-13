rule TrojanSpy_Win32_Bradop_B_2147655989_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bradop.B"
        threat_id = "2147655989"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bradop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 41 52 47 55 53 00 08 00 ff ff ff ff 06 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 dc 0b 8d 8d 4c ff ff ff b2 11 8b c6}  //weight: 1, accuracy: High
        $x_1_3 = {ff 53 60 6a 00 8b 45 ?? 0f b6 50 ?? b1 09 8b 45 00 e8 ?? ?? ?? ?? 8d 45 ?? 8b 15 ?? ?? ?? ?? 8b 12 e8 ?? ?? ?? ?? ba d0 07 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 ec 8b 55 f4 89 90 5c 02 00 00 c7 80 58 02 00 00 ?? ?? ?? ?? 8b 45 f8 8b 15 ?? ?? ?? ?? 8b 12 e8 ?? ?? ?? ?? 74 1c b2 01 8b 45 ec e8 ?? ?? ?? ?? 8b 45 ec 05 70 02 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 e8 0f b6 50 (0c|10) b1 07 8b 45 e8 e8 ?? ?? ?? ?? [0-21] ba e8 03 00 00 8b 45 e8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

