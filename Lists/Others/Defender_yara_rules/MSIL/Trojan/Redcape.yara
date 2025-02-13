rule Trojan_MSIL_Redcape_RPY_2147847648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcape.RPY!MTB"
        threat_id = "2147847648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcape"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "domakoskimadeireira.com.br" wide //weight: 1
        $x_1_2 = "Rnpnjaku.dll" wide //weight: 1
        $x_1_3 = "FromBase64String" wide //weight: 1
        $x_1_4 = "Array" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "HttpClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

