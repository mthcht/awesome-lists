rule Ransom_MSIL_W3CryptoLocker_SN_2147759729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/W3CryptoLocker.SN!MTB"
        threat_id = "2147759729"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "W3CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0c 2b 00 08 2a f0 00 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 14 14 17 8d ?? ?? ?? ?? 25 16 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? a2 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 0a 06 6f ?? ?? ?? ?? 16 9a 6f ?? ?? ?? ?? 19 9a 14 03 6f ?? ?? ?? ?? 0b 72}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_W3CryptoLocker_SM_2147759730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/W3CryptoLocker.SM!MTB"
        threat_id = "2147759730"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "W3CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {91 07 61 06 09 91 61 d2 9c f0 00 00 28 ?? ?? ?? ?? 03 6f ?? ?? ?? ?? 0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 17 58 8d ?? ?? ?? ?? 0c 16 0d 16 13 04 38 ?? ?? ?? ?? 00 08 11 04 02 11 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_W3CryptoLocker_SK_2147759731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/W3CryptoLocker.SK!MTB"
        threat_id = "2147759731"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "W3CryptoLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Attention!" ascii //weight: 5
        $x_5_2 = "W3CRYPTO LOCKER" ascii //weight: 5
        $x_1_3 = "Read_Me.txt" wide //weight: 1
        $x_1_4 = "select * from Win32_ShadowCopy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

