rule HackTool_MacOS_SuspTimestomp_P1_2147937944_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspTimestomp.P1"
        threat_id = "2147937944"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspTimestomp"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "touch -t" wide //weight: 10
        $x_10_2 = "touch -m" wide //weight: 10
        $x_10_3 = "touch -a" wide //weight: 10
        $x_10_4 = "touch -r" wide //weight: 10
        $x_10_5 = "touch -d" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

