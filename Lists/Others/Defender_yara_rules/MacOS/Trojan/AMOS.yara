rule Trojan_MacOS_AMOS_HAB_2147961361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AMOS.HAB!MTB"
        threat_id = "2147961361"
        type = "Trojan"
        platform = "MacOS: "
        family = "AMOS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f be 04 08 33 85 ?? ?? ff ff 88 c1 8b 85 ?? ?? ff ff 88 8c}  //weight: 20, accuracy: Low
        $x_5_2 = "@__ZN4mlcg4prngEj" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

