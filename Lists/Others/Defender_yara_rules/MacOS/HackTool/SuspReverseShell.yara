rule HackTool_MacOS_SuspReverseShell_A1_2147937943_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspReverseShell.A1"
        threat_id = "2147937943"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspReverseShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 00 6f 00 63 00 6b 00 65 00 74 00 [0-255] 2e 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 [0-255] 70 00 74 00 79 00 2e 00 73 00 70 00 61 00 77 00 6e 00 28 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

