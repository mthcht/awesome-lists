rule HackTool_Win32_Cyjecter_2147656471_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Cyjecter"
        threat_id = "2147656471"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyjecter"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "modinject" ascii //weight: 2
        $x_1_2 = "WelchGIFviewer.ucAniGIF" ascii //weight: 1
        $x_1_3 = {3a 00 5c 00 4d 00 61 00 69 00 6e 00 43 00 69 00 74 00 5c 00 [0-64] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 00 5c 00 63 00 69 00 74 00 65 00 72 00 5c 00 [0-64] 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Failed to Write DLL to Process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

