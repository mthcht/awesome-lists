rule HackTool_MacOS_SuspiciousTorCmd_A_2147775874_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspiciousTorCmd.A"
        threat_id = "2147775874"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspiciousTorCmd"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "torify" wide //weight: 10
        $x_10_2 = "torproxy" wide //weight: 10
        $x_10_3 = "install tor" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

