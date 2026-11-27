rule Trojan_Linux_MiraiFlooder_AMTB_2147982875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MiraiFlooder!AMTB"
        threat_id = "2147982875"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MiraiFlooder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "176.65.139.36" ascii //weight: 2
        $x_2_2 = "dc.us-pr.plainproxies.com" ascii //weight: 2
        $x_1_3 = "UDP_FLOOD" ascii //weight: 1
        $x_1_4 = "HTTPS_FLOOD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

