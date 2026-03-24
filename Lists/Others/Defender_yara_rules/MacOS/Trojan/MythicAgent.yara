rule Trojan_MacOS_MythicAgent_X4_2147965440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MythicAgent.X4"
        threat_id = "2147965440"
        type = "Trojan"
        platform = "MacOS: "
        family = "MythicAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "PostResponse" ascii //weight: 100
        $x_100_2 = "MythicID" ascii //weight: 100
        $x_100_3 = "json:\"killdate" ascii //weight: 100
        $x_100_4 = "json:\"payload" ascii //weight: 100
        $x_100_5 = "json:\"socks" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

