rule HackTool_Win32_Wrokni_C_2147735107_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Wrokni.C"
        threat_id = "2147735107"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Wrokni"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "h_LE_" ascii //weight: 10
        $x_1_2 = "BugSignature" wide //weight: 1
        $x_1_3 = "VideoDriver service" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

