rule Ransom_MSIL_CashCrypt_PA_2147909765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CashCrypt.PA!MTB"
        threat_id = "2147909765"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CashCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CashRansomware.KeyAuth" ascii //weight: 1
        $x_1_2 = "get_Monero_Logo_svg" ascii //weight: 1
        $x_1_3 = "AES_Encrypt" ascii //weight: 1
        $x_1_4 = "get_monero_icon_512x512_kqg9n5mp" ascii //weight: 1
        $x_1_5 = "CashRansomware.UnknownF1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

