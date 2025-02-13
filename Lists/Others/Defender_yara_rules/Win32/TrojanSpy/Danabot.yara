rule TrojanSpy_Win32_Danabot_E_2147733578_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Danabot.E!bit"
        threat_id = "2147733578"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Danabot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b e8 8d b5 ?? ?? ?? ?? 4e 83 c6 04 81 e6 00 00 ff ff 6a 04 68 00 10 10 00 56 6a 00 e8 ?? ?? ?? ?? 8b d8 85 db}  //weight: 1, accuracy: Low
        $x_1_2 = {51 56 57 8b 75 ?? 8b 7d ?? 8b 4d ?? f3 a4 5f 5e 59}  //weight: 1, accuracy: Low
        $x_1_3 = {50 8b 45 fc 50 6a 00 6a ff 6a 00 8b 45 ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {89 47 04 89 18 c6 05 74 ?? ?? ?? ?? 83 c3 10 8b c3 11 00 a1 ?? ?? ?? ?? c7 07 ?? ?? ?? ?? 89 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

