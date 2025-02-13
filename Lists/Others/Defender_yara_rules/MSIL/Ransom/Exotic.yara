rule Ransom_MSIL_Exotic_PA_2147769422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Exotic.PA!MTB"
        threat_id = "2147769422"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Exotic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exotic" wide //weight: 1
        $x_1_2 = "Windows are Infected, by the EXOTIC Virus!" wide //weight: 1
        $x_1_3 = "kill your PC!" wide //weight: 1
        $x_1_4 = "fucked by EXOTIC SQUAD!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

