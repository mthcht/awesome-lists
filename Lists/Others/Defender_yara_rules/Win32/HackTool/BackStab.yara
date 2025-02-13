rule HackTool_Win32_BackStab_A_2147913801_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/BackStab.A"
        threat_id = "2147913801"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BackStab"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\Backstab.pdb" ascii //weight: 5
        $x_5_2 = "Killing process" ascii //weight: 5
        $x_1_3 = "\\device\\procexp" ascii //weight: 1
        $x_1_4 = "procexp.pdb" ascii //weight: 1
        $x_1_5 = {70 00 72 00 6f 00 63 00 65 00 78 00 70 00 [0-12] 2e 00 73 00 79 00 73 00}  //weight: 1, accuracy: Low
        $x_1_6 = {70 72 6f 63 65 78 70 [0-12] 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_7 = "procexp64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

