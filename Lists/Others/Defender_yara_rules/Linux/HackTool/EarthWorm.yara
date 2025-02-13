rule HackTool_Linux_EarthWorm_B_2147921057_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/EarthWorm.B!MTB"
        threat_id = "2147921057"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "EarthWorm"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "./xxx -h -s ssocksd" ascii //weight: 2
        $x_2_2 = "./ew -s rssocks -d xxx.xxx.xxx.xxx -e 8888" ascii //weight: 2
        $x_1_3 = "rootkiter.com/EarthWrom/" ascii //weight: 1
        $x_1_4 = "./ew -s lcx_slave -d [ref_ip]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

