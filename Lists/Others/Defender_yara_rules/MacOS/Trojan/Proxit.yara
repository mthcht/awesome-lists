rule Trojan_MacOS_Proxit_A_2147820289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Proxit.A"
        threat_id = "2147820289"
        type = "Trojan"
        platform = "MacOS: "
        family = "Proxit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "proxit.com/peer" ascii //weight: 1
        $x_1_2 = "CncAddress" ascii //weight: 1
        $x_1_3 = "proxit.com/common/config.loadViper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Proxit_B_2147828450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Proxit.B"
        threat_id = "2147828450"
        type = "Trojan"
        platform = "MacOS: "
        family = "Proxit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "proxit.com/common/config.loadViper" ascii //weight: 1
        $x_1_2 = "/cnc/grpcmodels.(*Peer)" ascii //weight: 1
        $x_1_3 = "proxit.com/common/hostinfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

