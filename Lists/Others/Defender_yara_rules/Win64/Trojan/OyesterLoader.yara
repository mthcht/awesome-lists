rule Trojan_Win64_OyesterLoader_OSH_2147922580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OyesterLoader.OSH!MTB"
        threat_id = "2147922580"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OyesterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 59 10 48 8b d3 48 8b 4a 60 45 8b ce 48 8b c1 66 44 39 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

