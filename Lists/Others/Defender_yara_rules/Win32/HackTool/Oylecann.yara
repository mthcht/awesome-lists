rule HackTool_Win32_Oylecann_A_2147641076_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Oylecann.A"
        threat_id = "2147641076"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Oylecann"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XXPFlooder" ascii //weight: 1
        $x_1_2 = "HTTPFlooder" ascii //weight: 1
        $x_1_3 = "LOIC.Properties" ascii //weight: 1
        $x_1_4 = "get_IsFlooding" ascii //weight: 1
        $x_1_5 = "get_FloodCount" ascii //weight: 1
        $x_1_6 = "txtTargetURL" wide //weight: 1
        $x_1_7 = "LOIC.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

