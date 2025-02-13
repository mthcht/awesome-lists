rule Trojan_MSIL_RatInjector_2147778323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RatInjector!MTB"
        threat_id = "2147778323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RatInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello" wide //weight: 1
        $x_1_2 = "Location" wide //weight: 1
        $x_1_3 = "Request failed. {0}" wide //weight: 1
        $x_1_4 = "https://api.stormpath.com/v1/tenants/current" wide //weight: 1
        $x_1_5 = "application/json" wide //weight: 1
        $x_1_6 = "Basic" wide //weight: 1
        $x_1_7 = "{0}:{1}" wide //weight: 1
        $x_1_8 = "Your_Stormpath_API_key_ID" wide //weight: 1
        $x_1_9 = "Your_Stormpath_API_key_secret" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

