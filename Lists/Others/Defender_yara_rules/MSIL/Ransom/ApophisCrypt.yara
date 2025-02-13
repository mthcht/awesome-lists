rule Ransom_MSIL_ApophisCrypt_PA_2147918930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ApophisCrypt.PA!MTB"
        threat_id = "2147918930"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ApophisCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".apop" wide //weight: 1
        $x_3_2 = "At this point, all of your files are encrypted" wide //weight: 3
        $x_1_3 = {5c 41 70 6f 70 68 69 73 5c [0-8] 5c [0-8] 5c 41 70 6f 70 68 69 73 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

