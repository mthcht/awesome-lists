rule PWS_MSIL_Stelega_ZA_2147773173_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Stelega.ZA!MTB"
        threat_id = "2147773173"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stelega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AZJCJfpyUsnAfJiyTLOifhLwQLhZwGQnrnOfJOnTpCiTDfBnyfynAAJxwhxnBJTLsQ" wide //weight: 1
        $x_1_2 = "yhxGkJfDMpTfiUkihOywMGfEhwUUQLLMnQOsEBvpnBEZUkExQhTyUQhJwkMJAisikT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

