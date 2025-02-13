rule Trojan_AndroidOS_Mania_A_2147841984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mania.A!MTB"
        threat_id = "2147841984"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mania"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/alk/copilot/marketplace/eu/full" ascii //weight: 1
        $x_1_2 = "SendThem" ascii //weight: 1
        $x_1_3 = "getMessageBody" ascii //weight: 1
        $x_1_4 = "CoPilotLiveEuropeActivity" ascii //weight: 1
        $x_1_5 = "bGoodNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

