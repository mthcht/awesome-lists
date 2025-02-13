rule Trojan_MacOS_HackBrow_A_2147841565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HackBrow.A!MTB"
        threat_id = "2147841565"
        type = "Trojan"
        platform = "MacOS: "
        family = "HackBrow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "hack-browser-data/" ascii //weight: 5
        $x_1_2 = "/browingdata/creditcard/creditcard" ascii //weight: 1
        $x_1_3 = "provider.PickBrowsers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

