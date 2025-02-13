rule Ransom_MSIL_BearCrypt_SK_2147753434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BearCrypt.SK!MTB"
        threat_id = "2147753434"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BearCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Bear.exe" ascii //weight: 5
        $x_1_2 = "fuWinIni" ascii //weight: 1
        $x_1_3 = "RSAEncrypt" ascii //weight: 1
        $x_1_4 = "AESEncrypt" ascii //weight: 1
        $x_1_5 = "encryptStr" ascii //weight: 1
        $x_1_6 = "MaMo434376 Protector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_BearCrypt_SM_2147753438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BearCrypt.SM!MTB"
        threat_id = "2147753438"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BearCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {5c 42 65 61 72 5c 6f 62 6a 5c [0-16] 5c 42 65 61 72 2e 70 64 62}  //weight: 20, accuracy: Low
        $x_5_2 = ".crypt" wide //weight: 5
        $x_5_3 = "\\Readme.txt" wide //weight: 5
        $x_5_4 = "c:\\1.jpg" wide //weight: 5
        $x_1_5 = ".jpg" wide //weight: 1
        $x_1_6 = ".html" wide //weight: 1
        $x_1_7 = ".png" wide //weight: 1
        $x_1_8 = ".iso" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

