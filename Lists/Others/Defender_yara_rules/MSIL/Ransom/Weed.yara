rule Ransom_MSIL_Weed_DA_2147775159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Weed.DA!MTB"
        threat_id = "2147775159"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Weed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware.tor" ascii //weight: 1
        $x_1_2 = ".weed" ascii //weight: 1
        $x_1_3 = ".onion" ascii //weight: 1
        $x_1_4 = "wallpaper.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

