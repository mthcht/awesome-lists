rule TrojanDropper_Win32_Glaze_C_2147611351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Glaze.C"
        threat_id = "2147611351"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Glaze"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 02 5f c6 06 4d 39 7d f4 c6 46 01 5a 76 25 89 5d f8 29 75 f8 8b c7 6a 09 99 5b 8d 0c 37 f7 fb 8a c2 b2 03 f6 ea 8b 55 f8 32 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

