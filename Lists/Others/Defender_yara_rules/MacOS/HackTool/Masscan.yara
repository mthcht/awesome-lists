rule HackTool_MacOS_Masscan_A_2147922825_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Masscan.A!MTB"
        threat_id = "2147922825"
        type = "HackTool"
        platform = "MacOS: "
        family = "Masscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "masscan --nmap" ascii //weight: 1
        $x_1_2 = "massip-rangesv4.c" ascii //weight: 1
        $x_1_3 = "masscan-test" ascii //weight: 1
        $x_1_4 = "unicornscan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

