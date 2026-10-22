rule Trojan_MSIL_JitomirStealer_AMTB_2147980797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/JitomirStealer!AMTB"
        threat_id = "2147980797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JitomirStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JitomirStealer" ascii //weight: 2
        $x_1_2 = "StealWifi" ascii //weight: 1
        $x_1_3 = "StealPasswords" ascii //weight: 1
        $x_1_4 = "StealWallets" ascii //weight: 1
        $x_1_5 = "card_number_encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

