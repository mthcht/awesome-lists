rule MonitoringTool_AndroidOS_Faceniff_181560_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Faceniff"
        threat_id = "181560"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Faceniff"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "faceniff_intent" ascii //weight: 1
        $x_1_2 = "fetch_facebook" ascii //weight: 1
        $x_1_3 = "fetch_amazon" ascii //weight: 1
        $x_1_4 = "-j DNAT -p tcp --dport 1337 " ascii //weight: 1
        $x_1_5 = "sniffing: all services" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

