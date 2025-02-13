rule Trojan_MacOS_Morcut_A_2147748067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Morcut.A!MTB"
        threat_id = "2147748067"
        type = "Trojan"
        platform = "MacOS: "
        family = "Morcut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OvzD7xFr.app" ascii //weight: 1
        $x_1_2 = "C:\\RCSDB\\tmp\\bui7A1OvzD7xFr.app" ascii //weight: 1
        $x_1_3 = "8oTHYMCj.XIl" ascii //weight: 1
        $x_1_4 = "__MPRESS__v.2.12" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Morcut_C_2147752882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Morcut.C"
        threat_id = "2147752882"
        type = "Trojan"
        platform = "MacOS: "
        family = "Morcut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.apple.mdworker.plist" ascii //weight: 2
        $x_1_2 = "mdworker.flg" ascii //weight: 1
        $x_1_3 = "%@:staff" ascii //weight: 1
        $x_1_4 = "_executeTask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

