rule Trojan_MacOS_BlackHole_A_2147747916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/BlackHole.A!MTB"
        threat_id = "2147747916"
        type = "Trojan"
        platform = "MacOS: "
        family = "BlackHole"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BlackHole RAT -->" ascii //weight: 1
        $x_1_2 = "SpyFunctionsRecordiSightAudio" ascii //weight: 1
        $x_1_3 = "SystemAutoDeactivate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

