rule Ransom_MSIL_Seal_AMTB_2147981241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Seal!AMTB"
        threat_id = "2147981241"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Seal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TongaySeal777" ascii //weight: 1
        $x_2_2 = "Global\\SealCryptUniqueMutexName" ascii //weight: 2
        $x_2_3 = ".seal" ascii //weight: 2
        $x_1_4 = "SEALCRYPT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

