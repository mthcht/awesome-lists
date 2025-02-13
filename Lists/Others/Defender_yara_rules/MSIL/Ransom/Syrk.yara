rule Ransom_MSIL_Syrk_AD_2147742382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Syrk.AD"
        threat_id = "2147742382"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Syrk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your personal files are being encrypted by Syrk Malware. Your photos, videos, documents, etc..." wide //weight: 1
        $x_1_2 = "the only way to recover it is to contact this email: (panda831@protonmail.com) and submit your id." wide //weight: 1
        $x_1_3 = "SyrkProject.exe" ascii //weight: 1
        $x_1_4 = "get_dh35s3h8d69s3b1k" ascii //weight: 1
        $x_1_5 = "DisableAntiSpyware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Syrk_ST_2147762526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Syrk.ST!MTB"
        threat_id = "2147762526"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Syrk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Documents\\DeleteFile.exe" ascii //weight: 1
        $x_1_2 = "Your personal files are being encrypted by Syrk Malware." ascii //weight: 1
        $x_1_3 = "After paying, you will be sent a password that will be used to decrypt your files" ascii //weight: 1
        $x_1_4 = "if you don't do these actions before the timer expires your files will start to be deleted" ascii //weight: 1
        $x_1_5 = "All the files in the Desktop folder have been deleted!" ascii //weight: 1
        $x_1_6 = "*.Syrk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

