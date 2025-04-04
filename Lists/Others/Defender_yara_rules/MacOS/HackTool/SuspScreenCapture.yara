rule HackTool_MacOS_SuspScreenCapture_A1_2147937940_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspScreenCapture.A1"
        threat_id = "2147937940"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspScreenCapture"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "screencapture -x /tmp/" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

