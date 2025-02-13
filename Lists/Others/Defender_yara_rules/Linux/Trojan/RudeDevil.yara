rule Trojan_Linux_RudeDevil_A_2147764486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RudeDevil.A!MTB"
        threat_id = "2147764486"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RudeDevil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stratum+tcp://" ascii //weight: 1
        $x_1_2 = "m not rude at all" ascii //weight: 1
        $x_1_3 = {8b 45 f8 48 3b 45 e0 73 2d 48 8b 45 e8 0f b6 00 2a 45 f7 89 c2 48 8b 45 e8 88 10 48 8b 45 e8 48 8d 50 01 48 89 55 e8 0f b6 10 32 55 f7 88 10 48 83 45 f8 01 eb c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_RudeDevil_B_2147908237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RudeDevil.B!MTB"
        threat_id = "2147908237"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RudeDevil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DealwithDDoS" ascii //weight: 1
        $x_1_2 = "WZUdp_Flood" ascii //weight: 1
        $x_1_3 = "CCAttack" ascii //weight: 1
        $x_1_4 = "ICMPFlood" ascii //weight: 1
        $x_1_5 = "TCP_Flood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

