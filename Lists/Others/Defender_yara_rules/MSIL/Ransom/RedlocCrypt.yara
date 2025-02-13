rule Ransom_MSIL_RedlocCrypt_PA_2147785063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RedlocCrypt.PA!MTB"
        threat_id = "2147785063"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlocCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Ransomnote" ascii //weight: 1
        $x_1_2 = "/c taskkill /im explorer.exe /f" ascii //weight: 1
        $x_1_3 = "your files will be deleted forever" ascii //weight: 1
        $x_1_4 = {5c 52 65 64 65 72 5f 6c 6f 63 6b 5c [0-16] 5c [0-16] 5c 52 65 64 65 72 5f 6c 6f 63 6b 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

