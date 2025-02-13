rule HackTool_Win32_Granier_A_2147740035_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Granier.A!dha"
        threat_id = "2147740035"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Granier"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Jason - Exchange Mail BF - v " wide //weight: 3
        $x_2_2 = "Jason\\obj\\Release\\Jason.pdb" ascii //weight: 2
        $x_1_3 = "Email check time per Thread :" wide //weight: 1
        $x_1_4 = "Add to Username Start :" wide //weight: 1
        $x_1_5 = "Downloading \"{0}\" Emails :" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

