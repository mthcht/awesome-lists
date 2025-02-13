rule Trojan_iPhoneOS_Xagent_A_2147762527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/Xagent.A!MTB"
        threat_id = "2147762527"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "Xagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://198.27.64.218/" ascii //weight: 1
        $x_1_2 = "var/mobile/Library/SMS/sms.db" ascii //weight: 1
        $x_1_3 = "work/IOS_PROJECT/XAgent/XAgent/Reachability.m" ascii //weight: 1
        $x_1_4 = "ftp://localhost/IphoneData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_iPhoneOS_Xagent_B_2147762597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/Xagent.B!MTB"
        threat_id = "2147762597"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "Xagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "callRec.dylib.ba964c90.unsigned" ascii //weight: 1
        $x_1_2 = "/var/trastLOg/%@" ascii //weight: 1
        $x_1_3 = "mic.caf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

