rule Trojan_Linux_Skidmap_A_2147748749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Skidmap.A!MTB"
        threat_id = "2147748749"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Skidmap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "iproute.ko netlink.ko cryptov2.ko" ascii //weight: 2
        $x_1_2 = "kaudited kswaped irqbalanced rctlcli systemd-network pamdicks" ascii //weight: 1
        $x_1_3 = "/bin/mv pamdicks.org /tmp/mmm" ascii //weight: 1
        $x_1_4 = "/tmp/miner2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

