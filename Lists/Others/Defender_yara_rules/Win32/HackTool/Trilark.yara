rule HackTool_Win32_Trilark_A_2147749453_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Trilark.A!dha"
        threat_id = "2147749453"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Trilark"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 00 00 77 62 00 00 54 68 65 20 66 69 6c 65 20 63 6f 77 62 6f 79 20 69 73 6e 27 74 20 74 68 65 72 65 21 00 00 00 00 72 62 00 00 63 6f 77 62 6f 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Trilark_B_2147749454_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Trilark.B!dha"
        threat_id = "2147749454"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Trilark"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "north korea" ascii //weight: 1
        $x_1_2 = "http://ksi/spy/" ascii //weight: 1
        $x_1_3 = "spy\\help.txt" ascii //weight: 1
        $x_1_4 = "spy\\doc.php" ascii //weight: 1
        $x_1_5 = "__shellcode__" ascii //weight: 1
        $x_1_6 = "vbs obscure OK." ascii //weight: 1
        $x_1_7 = ".vbsobs" ascii //weight: 1
        $x_1_8 = "certutil -f -decode" ascii //weight: 1
        $x_1_9 = "Spy URL:" wide //weight: 1
        $x_1_10 = "asist encrypt" wide //weight: 1
        $x_1_11 = "asist decrypt" wide //weight: 1
        $x_1_12 = "Recovery HTA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

