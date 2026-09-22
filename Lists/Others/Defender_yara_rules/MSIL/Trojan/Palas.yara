rule Trojan_MSIL_Palas_MG_2147978581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Palas.MG!MTB"
        threat_id = "2147978581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Palas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_2 = "AntiSkidDLL.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

