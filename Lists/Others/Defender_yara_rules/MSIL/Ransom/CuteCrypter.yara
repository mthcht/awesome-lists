rule Ransom_MSIL_CuteCrypter_PA_2147771971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CuteCrypter.PA!MTB"
        threat_id = "2147771971"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CuteCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = ".locky" wide //weight: 5
        $x_5_2 = ".RekenSom" wide //weight: 5
        $x_4_3 = "cuteRansomware" wide //weight: 4
        $x_1_4 = "sendBack.txt" wide //weight: 1
        $x_1_5 = "secret.txt" wide //weight: 1
        $x_1_6 = "secretAES.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

