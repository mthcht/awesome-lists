rule Trojan_MacOS_MythicPoseidon_A_2147931807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MythicPoseidon.A!MTB"
        threat_id = "2147931807"
        type = "Trojan"
        platform = "MacOS: "
        family = "MythicPoseidon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/update_c2.go" ascii //weight: 1
        $x_1_2 = "github.com/MythicAgents/" ascii //weight: 1
        $x_1_3 = "/utils/p2p/poseidon_tcp.go" ascii //weight: 1
        $x_1_4 = "SendFileToMythic" ascii //weight: 1
        $x_1_5 = "*p2p.webshellResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

