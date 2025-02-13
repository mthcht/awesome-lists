rule Ransom_MSIL_RaNiros_ST_2147772417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RaNiros.ST!MTB"
        threat_id = "2147772417"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RaNiros"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All you important files are encrypted with AES 256 algoritm. No one can help you to restore" ascii //weight: 1
        $x_1_2 = "If you want to restore some your files for free write to email and attach 2-3 encrypted files" ascii //weight: 1
        $x_1_3 = "You have to pay to decrypt other files." ascii //weight: 1
        $x_1_4 = "As soon as we get bitcoins you'll get all your decrypted data back" ascii //weight: 1
        $x_1_5 = "Do not try decrypt encrypted files" ascii //weight: 1
        $x_1_6 = "But after 3 hours all your files will be deleted." ascii //weight: 1
        $x_1_7 = "/f /im Niros.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

