rule Ransom_MSIL_Nibiru_DA_2147765545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nibiru.DA!MTB"
        threat_id = "2147765545"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nibiru"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted with powerful military grade Ransomware" ascii //weight: 1
        $x_1_2 = "@protonmail.com" ascii //weight: 1
        $x_1_3 = ".Nibiru" ascii //weight: 1
        $x_1_4 = ".fucked" ascii //weight: 1
        $x_1_5 = "YOU HAVE BEEN HACKED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

