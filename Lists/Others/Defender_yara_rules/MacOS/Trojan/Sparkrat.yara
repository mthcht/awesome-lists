rule Trojan_MacOS_Sparkrat_B_2147933855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Sparkrat.B!MTB"
        threat_id = "2147933855"
        type = "Trojan"
        platform = "MacOS: "
        family = "Sparkrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spark/client/core.execCommand" ascii //weight: 1
        $x_1_2 = "Spark/client/common.(*Conn).GetSecretHex" ascii //weight: 1
        $x_1_3 = "Spark/client/core.killTerminal" ascii //weight: 1
        $x_1_4 = "Spark/client/core.uploadTextFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

