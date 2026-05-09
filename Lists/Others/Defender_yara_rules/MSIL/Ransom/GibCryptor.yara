rule Ransom_MSIL_GibCryptor_SN_2147968910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/GibCryptor.SN!MTB"
        threat_id = "2147968910"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GibCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This computer has been locked with a modern high-performance symmetric stream algorithm " wide //weight: 1
        $x_1_2 = "terrorist activity on the Internet " wide //weight: 1
        $x_1_3 = "Your system will automatically cease to exist and all data will be lost. " wide //weight: 1
        $x_1_4 = "destruction of the flash drive, OS image, and modification of MBR bytes." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

