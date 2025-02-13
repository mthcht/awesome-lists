rule TrojanDropper_Win32_Draobo_A_2147650513_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Draobo.A"
        threat_id = "2147650513"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Draobo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s..\\%X.dll" wide //weight: 1
        $x_1_2 = {8b 4c 3a 24 8b 44 3a 20 03 cf 89 4c 24 14 8b 4c 3a 18 55 03 c7 33 ed 85 c9 89 44 24 14 76 ?? eb 04 8b 44 24 14 8b 0c a8 8b 74 24 24 03 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

