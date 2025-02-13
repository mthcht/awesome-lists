rule TrojanDropper_Win32_Sengig_B_2147717568_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sengig.B"
        threat_id = "2147717568"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sengig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inst.vbs" ascii //weight: 1
        $x_1_2 = "%s\\Desktop\\Search.lnk" ascii //weight: 1
        $x_1_3 = "Dropper\\ReadMe.txt" wide //weight: 1
        $x_1_4 = "%CD%1/c start chrome http://searchengage.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Sengig_A_2147717569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sengig.A"
        threat_id = "2147717569"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sengig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\system32\\%s %s" ascii //weight: 1
        $x_1_2 = {c1 e9 10 23 c1 33 d0 8b 45 fc c1 e8 18 33 d0 8b 4d f8 c1 e9 08 23 4d f8 8b 45 f8 c1 e8 10 23 c8 33 d1 88 55 f7 8b 4d f8 c1 e9 08 8b 55 fc d1 ea 33 55 fc 81 e2 ff 00 00 00 c1 e2 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

