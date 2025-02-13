rule Ransom_MSIL_CyprenCrypt_PA_2147794486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CyprenCrypt.PA!MTB"
        threat_id = "2147794486"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CyprenCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LovinggPorn" wide //weight: 1
        $x_1_2 = "\\RECUPERAR__.porn.txt" wide //weight: 1
        $x_1_3 = ".porn" wide //weight: 1
        $x_1_4 = "files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

