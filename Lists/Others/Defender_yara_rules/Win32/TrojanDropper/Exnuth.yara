rule TrojanDropper_Win32_Exnuth_A_2147622787_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Exnuth.A"
        threat_id = "2147622787"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Exnuth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 10 40 39 d8 75 f3 06 00 80 28 ?? 80 30}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 6f 70 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

