rule Trojan_Linux_Winnti_2147764557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Winnti.bf!MTB"
        threat_id = "2147764557"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Winnti"
        severity = "Critical"
        info = "bf: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 53 31 3d 5b 1b 5b 30 3b 33 32 3b 34 30 6d 5c 75 40 5c 68 3a 5c 77 5d 5c 24}  //weight: 1, accuracy: High
        $x_1_2 = "HidePidPort" ascii //weight: 1
        $x_1_3 = "bypass_iptables" ascii //weight: 1
        $x_1_4 = "scandir" ascii //weight: 1
        $x_1_5 = "conf_DelAll_DNS" ascii //weight: 1
        $x_1_6 = "sendudp" ascii //weight: 1
        $x_1_7 = "hide.c" ascii //weight: 1
        $x_1_8 = "Get_AllIP" ascii //weight: 1
        $x_1_9 = "CB2FA36AAA9541F0Unknown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Linux_Winnti_A_2147770050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Winnti.A!!Winnti.A"
        threat_id = "2147770050"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Winnti"
        severity = "Critical"
        info = "Winnti: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 45 f0 c7 45 ec 08 01 00 00 c7 45 fc 28 00 00 00 eb 31 8b 45 fc 48 63 d0 48 8b 45 f0 48 01 c2 8b 45 fc 48 63 c8 48 8b 45 f0 48 01 c8 0f b6 00 89 c1 8b 45 f8 89 c6 8b 45 fc 01 f0 31 c8 88 02 83 45 fc 01}  //weight: 10, accuracy: High
        $x_1_2 = "get_our_pids" ascii //weight: 1
        $x_1_3 = "our_sockets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

