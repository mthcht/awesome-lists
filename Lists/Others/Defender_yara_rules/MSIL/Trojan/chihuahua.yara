rule Trojan_MSIL_chihuahua_ACH_2147942109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/chihuahua.ACH!MTB"
        threat_id = "2147942109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "chihuahua"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "https://flowers.hold-me-finger.xyz" wide //weight: 4
        $x_2_2 = "Snyal s mazhora cepi, ya povesil na sebya gold" wide //weight: 2
        $x_3_3 = "chihuahua" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

