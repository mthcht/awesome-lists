rule TrojanDropper_Win32_Chackill_A_2147626690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Chackill.A"
        threat_id = "2147626690"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Chackill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 66 75 63 6b 33 36 30 00}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_3 = ".256cha.cn" ascii //weight: 1
        $x_1_4 = ".php?tn=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

