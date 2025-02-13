rule Ransom_MSIL_BlackSkull_YAA_2147911749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackSkull.YAA!MTB"
        threat_id = "2147911749"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackSkull"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateDecryptor" ascii //weight: 1
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "NoCry.My.Resources" ascii //weight: 1
        $x_1_4 = "GetLogicalDrives" ascii //weight: 1
        $x_1_5 = "AES_Encrypt" ascii //weight: 1
        $x_1_6 = "files are encrypted" ascii //weight: 1
        $x_1_7 = "decrypt your files, yo need to pay" ascii //weight: 1
        $x_1_8 = "How Do I Pay?" ascii //weight: 1
        $x_1_9 = "buy some bitcoin" ascii //weight: 1
        $x_1_10 = "BlackSkull.exe" wide //weight: 1
        $x_1_11 = "Recover_Your_Files.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

