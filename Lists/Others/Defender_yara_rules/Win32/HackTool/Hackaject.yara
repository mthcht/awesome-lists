rule HackTool_Win32_Hackaject_2147656081_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Hackaject"
        threat_id = "2147656081"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Hackaject"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 73 00 69 00 6d 00 75 00 6c 00 61 00 73 00 69 00 [0-32] 62 00 69 00 73 00 61 00 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_2_2 = {5c 00 69 00 6e 00 6a 00 65 00 [0-32] 62 00 69 00 73 00 61 00 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_2_3 = "adf.ly" wide //weight: 2
        $x_1_4 = "\\Release\\PointBlank.pdb" ascii //weight: 1
        $x_1_5 = "PointBlank.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

