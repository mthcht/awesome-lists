rule HackTool_MacOS_RevAnthShell_A_2147981253_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/RevAnthShell.A"
        threat_id = "2147981253"
        type = "HackTool"
        platform = "MacOS: "
        family = "RevAnthShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ssh " wide //weight: 10
        $x_10_2 = "/.config/.smtk" wide //weight: 10
        $x_10_3 = "tunnel@134.209.82.225" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

