rule Trojan_MSIL_BazaarLoader_OSH_2147922631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BazaarLoader.OSH!MTB"
        threat_id = "2147922631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BazaarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMHub.dll" ascii //weight: 1
        $x_1_2 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_3 = "F00B95BA-951B-4AE5-B42D-E1641C5169B8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

