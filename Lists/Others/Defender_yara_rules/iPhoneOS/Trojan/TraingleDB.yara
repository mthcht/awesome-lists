rule Trojan_iPhoneOS_TraingleDB_A_2147850676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/TraingleDB.A!MTB"
        threat_id = "2147850676"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "TraingleDB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unmungeHexString" ascii //weight: 1
        $x_1_2 = "CRPwrInfo" ascii //weight: 1
        $x_1_3 = "CRConfig" ascii //weight: 1
        $x_1_4 = "CRXConfigureDBServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

