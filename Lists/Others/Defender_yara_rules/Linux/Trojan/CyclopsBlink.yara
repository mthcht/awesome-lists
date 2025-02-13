rule Trojan_Linux_CyclopsBlink_B_2147818562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CyclopsBlink.B!MTB"
        threat_id = "2147818562"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CyclopsBlink"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/pending/bin/install_upgraded" ascii //weight: 1
        $x_1_2 = "/pending/bin/S51armled" ascii //weight: 1
        $x_1_3 = "/pending/bin/busybox-rel" ascii //weight: 1
        $x_1_4 = "install_payload" ascii //weight: 1
        $x_1_5 = "/pending/WGUpgrade-dl.new" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

