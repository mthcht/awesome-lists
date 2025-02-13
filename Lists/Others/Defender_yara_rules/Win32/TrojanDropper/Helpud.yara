rule TrojanDropper_Win32_Helpud_B_2147619073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Helpud.B"
        threat_id = "2147619073"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Helpud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 78 05 90 75 19 80 78 06 f0 75 13 80 78 07 b9 75 0d 80 78 08 43 75 07}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 00 a5 8c 8b 55 ?? 41 40 d1 ea 40 3b ca 72 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

