rule Trojan_Linux_AutoColor_A_2147940006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/AutoColor.A!MTB"
        threat_id = "2147940006"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "AutoColor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "auto-color" ascii //weight: 2
        $x_2_2 = "/door-%d.log" ascii //weight: 2
        $x_1_3 = "/proc/net/tcp" ascii //weight: 1
        $x_1_4 = "/etc/ld.so.preload.xxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

