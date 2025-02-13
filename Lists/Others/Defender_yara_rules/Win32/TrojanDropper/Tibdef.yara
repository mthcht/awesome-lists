rule TrojanDropper_Win32_Tibdef_A_2147643062_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tibdef.A"
        threat_id = "2147643062"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibdef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 3a 5c 50 72 6f 6a 65 6b 74 79 5c 45 76 75 6c 53 6f 66 74 5c 54 69 62 69 53 61 76 65 50 61 73 73 5c 50 72 6f 67 72 61 6d 79 5c 53 74 75 62 20 56 49 53 55 41 4c 5c 52 65 6c 65 61 73 65 5c 53 74 75 62 20 56 49 53 55 41 4c 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 65 73 69 6e 67 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 6c 6b 61 72 65 2e 66 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Tibdef_B_2147648185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tibdef.B"
        threat_id = "2147648185"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tibdef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "D:\\Projekty\\EvulSoft\\TibiSavePass\\Programy\\Stub VISUAL\\Release\\Stub VISUAL.pdb" ascii //weight: 5
        $x_3_2 = "--@Count----h--" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

