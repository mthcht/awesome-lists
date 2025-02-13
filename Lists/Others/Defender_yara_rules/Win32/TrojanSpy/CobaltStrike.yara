rule TrojanSpy_Win32_CobaltStrike_STE_2147767399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/CobaltStrike.STE!!CobaltStrike.STE"
        threat_id = "2147767399"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "CobaltStrike: an internal category used to refer to some threats"
        info = "STE: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 89 00 00 00 60 89 e5 31 d2 64 8b 52 30 8b 52 0c 8b 52 14}  //weight: 1, accuracy: High
        $x_1_2 = {2f 70 6f 73 74 73 2f [0-16] 2f 69 76 63 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {e9 91 01 00 00 e9 c9 01 00 00 e8 8b ff ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {68 6e 65 74 00 68 77 69 6e 69 ?? 68 4c 77 26 07 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

