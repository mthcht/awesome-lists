rule TrojanDropper_Win32_Emptybase_A_2147605138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Emptybase.A"
        threat_id = "2147605138"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Emptybase"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 7d f8 76 18 33 d2 6a 03 8b c1 5e f7 f6 28 91 08 40 40 00 41 3b 0d 04 40 40 00 72 e8 39 1d 00 40 40 00 89 5d f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

