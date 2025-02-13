rule TrojanClicker_Win32_Yumud_A_2147648472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Yumud.A"
        threat_id = "2147648472"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Yumud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {db 45 fc dd 5d ec dd 45 ec db 45 f8 dd 5d e4 dc 65 e4 dd 5d dc dd 45 dc dc 05 ?? ?? ?? ?? dd 5d d4 dd 45 d4 e8}  //weight: 10, accuracy: Low
        $x_1_2 = {75 72 6c 00 00 68 74 74 70 3a 2f 2f 00 2f 73 3f 00 2f 62 61 69 64 75 3f 00 74 69 74 6c 65 00 3f 71 75 65 72 79 3d 00 2f 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 1, accuracy: High
        $x_1_3 = {75 72 6c 00 00 68 74 74 70 3a 2f 2f 00 2f 73 3f 00 2f 62 61 69 64 75 3f 00 3f 71 75 65 72 79 3d 00 2f 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

