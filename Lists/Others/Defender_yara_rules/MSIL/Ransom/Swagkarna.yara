rule Ransom_MSIL_Swagkarna_2147778518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Swagkarna!MTB"
        threat_id = "2147778518"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Swagkarna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyPrivateKey" wide //weight: 1
        $x_1_2 = ".swagkarna" wide //weight: 1
        $x_1_3 = "crypted :" wide //weight: 1
        $x_1_4 = "C:\\Users\\" wide //weight: 1
        $x_1_5 = ".png" wide //weight: 1
        $x_1_6 = ".html" wide //weight: 1
        $x_1_7 = ".cpp" wide //weight: 1
        $x_1_8 = ".txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

