rule Ransom_MSIL_Jasmin_DA_2147785226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Jasmin.DA!MTB"
        threat_id = "2147785226"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jasmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Jasmin Encryptor" ascii //weight: 1
        $x_1_2 = "unlock your files" ascii //weight: 1
        $x_1_3 = ".ransimulator" ascii //weight: 1
        $x_1_4 = "bytesToBeEncrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Jasmin_DB_2147788437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Jasmin.DB!MTB"
        threat_id = "2147788437"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jasmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Jasmin Encryptor" ascii //weight: 1
        $x_1_2 = ".jasmin" ascii //weight: 1
        $x_1_3 = "error ha bhaiya" ascii //weight: 1
        $x_1_4 = "jasmin@123" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

