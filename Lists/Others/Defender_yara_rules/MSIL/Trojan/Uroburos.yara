rule Trojan_MSIL_Uroburos_MCV_2147967765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Uroburos.MCV!MTB"
        threat_id = "2147967765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Uroburos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "168C03000001A22518168C03000001A214" wide //weight: 1
        $x_1_2 = "6C00635154694F69636876686F7152374E" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Uroburos_MCW_2147967766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Uroburos.MCW!MTB"
        threat_id = "2147967766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Uroburos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "87B10C9B602F" ascii //weight: 1
        $x_1_2 = "SafeLsaPolicy.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

