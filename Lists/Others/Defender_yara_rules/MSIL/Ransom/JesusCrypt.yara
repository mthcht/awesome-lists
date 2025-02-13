rule Ransom_MSIL_JesusCrypt_PA_2147744911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/JesusCrypt.PA!MTB"
        threat_id = "2147744911"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JesusCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&allow=ransom" wide //weight: 1
        $x_1_2 = "\\Desktop\\READ_IT_PRP.txt.prp" wide //weight: 1
        $x_1_3 = "\\Desktop\\READ_IT.txt.proced" wide //weight: 1
        $x_1_4 = {54 00 77 00 6f 00 6a 00 65 00 20 00 70 00 6c 00 69 00 6b 00 69 00 20 00 7a 00 6f 00 73 00 74 00 61 00 ?? ?? 79 00 20 00 7a 00 61 00 73 00 7a 00 79 00 66 00 72 00 6f 00 77 00 61 00 6e 00 65 00 2e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 00 72 00 6f 00 73 00 7a 00 ?? ?? 20 00 77 00 70 00 ?? ?? 61 00 63 00 69 00 ?? ?? 20 00 72 00 ?? ?? 77 00 6e 00 6f 00 77 00 61 00 72 00 74 00 6f 00 ?? ?? ?? ?? 20 00 32 00 30 00 30 00 20 00 50 00 4c 00 4e 00 20 00 6e 00 61 00 20 00 6b 00 6f 00 6e 00 74 00 6f 00 20 00 42 00 49 00 54 00 43 00 4f 00 49 00 4e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

