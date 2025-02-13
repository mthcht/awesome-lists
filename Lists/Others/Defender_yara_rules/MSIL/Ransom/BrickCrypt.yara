rule Ransom_MSIL_BrickCrypt_PA_2147817659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BrickCrypt.PA!MTB"
        threat_id = "2147817659"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BrickCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = ".brick" wide //weight: 1
        $x_1_3 = "\\ID_GENERATE.TXT" wide //weight: 1
        $x_1_4 = "DON'T TOUCH THIS FILE!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

