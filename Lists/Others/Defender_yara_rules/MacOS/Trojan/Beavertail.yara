rule Trojan_MacOS_Beavertail_B_2147921858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Beavertail.B!MTB"
        threat_id = "2147921858"
        type = "Trojan"
        platform = "MacOS: "
        family = "Beavertail"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upLDBFinished" ascii //weight: 1
        $x_1_2 = "Download Python Success!" ascii //weight: 1
        $x_1_3 = "clientDownFinished" ascii //weight: 1
        $x_1_4 = "Download Client Success!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

