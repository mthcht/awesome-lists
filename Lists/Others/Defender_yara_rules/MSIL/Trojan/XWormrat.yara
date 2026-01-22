rule Trojan_MSIL_XWormrat_RR_2147961593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWormrat.RR!MTB"
        threat_id = "2147961593"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWormrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "45fcaf70-bd7c-4ea0-911b-55fa73aa368d" ascii //weight: 1
        $x_1_2 = "BD2.Net Injector.exe" wide //weight: 1
        $x_1_3 = "BD2.Net_Injector.Properties.Resources" wide //weight: 1
        $x_1_4 = "BD2_copy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

