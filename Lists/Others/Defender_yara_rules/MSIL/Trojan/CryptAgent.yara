rule Trojan_MSIL_CryptAgent_SA_2147744372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptAgent.SA!MTB"
        threat_id = "2147744372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\myapp.exe" ascii //weight: 1
        $x_1_2 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_3 = "op_Equality" ascii //weight: 1
        $x_1_4 = "op_Inequality" ascii //weight: 1
        $x_1_5 = "\\MyApp.log" ascii //weight: 1
        $x_1_6 = "TimeLogger(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

