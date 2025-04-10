rule Ransom_MSIL_EncnCrypt_PA_2147938480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/EncnCrypt.PA!MTB"
        threat_id = "2147938480"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EncnCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%BTC%" wide //weight: 1
        $x_1_2 = "Background.bmp" wide //weight: 1
        $x_1_3 = "\\How To Decrypt My Files.html" wide //weight: 1
        $x_2_4 = "Ransomware Files Already Encrypted!" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

