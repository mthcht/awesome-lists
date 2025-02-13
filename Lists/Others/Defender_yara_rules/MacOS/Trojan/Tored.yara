rule Trojan_MacOS_Tored_B_2147745413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Tored.B!MTB"
        threat_id = "2147745413"
        type = "Trojan"
        platform = "MacOS: "
        family = "Tored"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "br@fh.tn" ascii //weight: 1
        $x_1_2 = "av@av.tn" ascii //weight: 1
        $x_1_3 = "fucker@fuck.fu" ascii //weight: 1
        $x_1_4 = "ser@jhfd.it" ascii //weight: 1
        $x_1_5 = "Introspection.GenericPrimitiveTypeInfo" ascii //weight: 1
        $x_7_6 = "Infected and boted by OSX.Raedbot.B++" ascii //weight: 7
        $x_5_7 = "keyloger started" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Tored_A_2147750317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Tored.A!MTB"
        threat_id = "2147750317"
        type = "Trojan"
        platform = "MacOS: "
        family = "Tored"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Infected and boted by OSX.Raedbot.D" ascii //weight: 2
        $x_1_2 = "spam.targets" ascii //weight: 1
        $x_1_3 = "keyloger started" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

