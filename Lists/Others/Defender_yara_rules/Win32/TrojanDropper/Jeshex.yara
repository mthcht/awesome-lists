rule TrojanDropper_Win32_Jeshex_A_2147619813_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Jeshex.A"
        threat_id = "2147619813"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Jeshex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 d0 80 fa 00 74}  //weight: 1, accuracy: High
        $x_1_2 = {ff 75 14 6a 02 6a 00 6a 00 68 00 00 00 c0}  //weight: 1, accuracy: High
        $x_1_3 = {ff 75 18 6a 00 ff 75 28 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

