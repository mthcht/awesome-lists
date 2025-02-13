rule Ransom_MSIL_Payola_PA_2147890427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Payola.PA!MTB"
        threat_id = "2147890427"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Payola"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Payola" wide //weight: 1
        $x_1_2 = "Recovery_Guide.html" wide //weight: 1
        $x_1_3 = "\\Recovery_ID.txt" wide //weight: 1
        $x_1_4 = "File Encrypted:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Payola_ZC_2147892753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Payola.ZC!MTB"
        threat_id = "2147892753"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Payola"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryption Completed in {0} ms" wide //weight: 1
        $x_1_2 = "Encrypting Drive:" wide //weight: 1
        $x_1_3 = "Deleted Backups & Volume Shadow Copies" wide //weight: 1
        $x_1_4 = "Payola.pdb" ascii //weight: 1
        $x_1_5 = "Your data was encrypted by Payola" ascii //weight: 1
        $x_1_6 = "Outlook Files\\honey@pot.com.pst" wide //weight: 1
        $x_1_7 = "Encrypted Path:" wide //weight: 1
        $x_1_8 = "Payola Locker" wide //weight: 1
        $x_1_9 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

