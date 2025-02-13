rule TrojanDropper_Win32_Taterf_A_2147618703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Taterf.A"
        threat_id = "2147618703"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Taterf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 8b 10 83 c0 02 66 81 f2 ?? ?? 81 ea ?? ?? ?? ?? 41 66 89 50 fe 8b 96 ?? ?? 00 00 d1 ea 3b ca 72 de}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 51 02 83 fa 68 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8a 48 03 83 f9 13 75 08 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 6f 64 33 32 66 75 63 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

