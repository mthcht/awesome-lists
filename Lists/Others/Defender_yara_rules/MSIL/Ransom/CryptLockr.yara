rule Ransom_MSIL_CryptLockr_PA_2147819824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CryptLockr.PA!MTB"
        threat_id = "2147819824"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptLockr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoLocker2.0_RANSOMWARE" wide //weight: 1
        $x_1_2 = "shutdown /s /t 0" wide //weight: 1
        $x_1_3 = "shield_PNG1275" wide //weight: 1
        $x_1_4 = "Your data is encrypted with a unique encryption algorythm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

