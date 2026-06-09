rule HackTool_MacOS_FlowOffsetCurl_A_2147971194_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/FlowOffsetCurl.A!dha"
        threat_id = "2147971194"
        type = "HackTool"
        platform = "MacOS: "
        family = "FlowOffsetCurl"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "curl " wide //weight: 10
        $x_1_2 = {2d 00 61 00 20 00 6d 00 61 00 63 00 2d 00 63 00 75 00 72 00 ?? ?? 20 00 2d 00 73 00 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "-A audio -s http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

