rule Trojan_Linux_RootKit_ZA_2147977346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RootKit.ZA!MTB"
        threat_id = "2147977346"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RootKit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 55 e8 48 8b 45 f8 48 01 d0 48 8b 4d e8 48 8b 55 f8 48 01 ca 0f b6 12 83 f2 ac 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 f0 72 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

