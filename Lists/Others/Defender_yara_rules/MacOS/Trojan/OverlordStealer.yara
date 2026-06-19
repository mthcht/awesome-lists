rule Trojan_MacOS_OverlordStealer_K_2147971925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/OverlordStealer.K!AMTB"
        threat_id = "2147971925"
        type = "Trojan"
        platform = "MacOS: "
        family = "OverlordStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OVERLORD_GUS_WORKSPACE" ascii //weight: 2
        $x_2_2 = "overlord-client/cmd/agent/" ascii //weight: 2
        $x_1_3 = "metamask" ascii //weight: 1
        $x_1_4 = "wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

