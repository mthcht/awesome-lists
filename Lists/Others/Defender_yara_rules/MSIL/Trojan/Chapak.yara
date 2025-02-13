rule Trojan_MSIL_Chapak_DI_2147795078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Chapak.DI!MTB"
        threat_id = "2147795078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adfasdas" ascii //weight: 1
        $x_1_2 = "SHOPPING_WORLD_ONLINE_ECOMMERCE_ICON_192440" wide //weight: 1
        $x_1_3 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "ResolveSignature" ascii //weight: 1
        $x_1_7 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

