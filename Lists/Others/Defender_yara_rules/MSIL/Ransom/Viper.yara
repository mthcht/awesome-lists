rule Ransom_MSIL_Viper_MK_2147807984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Viper.MK!MTB"
        threat_id = "2147807984"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Viper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Ransomware.Viper.A]" ascii //weight: 1
        $x_1_2 = "\\Viper_README.RW-SK.txt" ascii //weight: 1
        $x_1_3 = "Your files were encrypted by Viper Ransomware" ascii //weight: 1
        $x_1_4 = "Send $500 in BitCoins to this address:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

