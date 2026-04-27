rule Ransom_MSIL_Comrade_BH_2147967799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Comrade.BH!MSR"
        threat_id = "2147967799"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Comrade"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Comrade Circle" ascii //weight: 1
        $x_1_2 = "After decryption we will give you icon of Stalin that will protect you in future from others proud members" ascii //weight: 1
        $x_1_3 = "Decrypt you files" ascii //weight: 1
        $x_1_4 = "purchase decrytpion software" ascii //weight: 1
        $x_1_5 = "Send donation of $value btc to wallet $wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

