rule TrojanDropper_Win32_Swapexo_A_2147627480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Swapexo.A"
        threat_id = "2147627480"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Swapexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3b ef 73 1a 8a 08 84 c9 75 05 c6 00 58 eb 08 80 f9 58 75 03 c6 00 00 83 c0 01 3b c7 72 e6}  //weight: 2, accuracy: High
        $x_2_2 = "d:\\vsProjects\\iosetup\\Release\\iosetup.pdb" ascii //weight: 2
        $x_1_3 = {47 6c 6f 62 61 6c 5c 74 74 74 6d 6d 6d 74 74 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 74 74 6b 6b 6b 74 74 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {69 6f 66 69 6c 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Swapexo_B_2147712634_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Swapexo.B"
        threat_id = "2147712634"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Swapexo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {47 6c 6f 62 61 6c 5c 74 74 74 6d 6d 6d 74 74 74 00}  //weight: 5, accuracy: High
        $x_1_2 = {74 74 74 6b 6b 6b 74 74 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 72 78 78 25 64 3f 64 3d 25 64 26 66 31 3d 25 73 26 66 32 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "%s\\drivers\\%s.sys" ascii //weight: 1
        $x_1_5 = "UPDATESERVER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

