rule Trojan_MSIL_SecoStealer_AMTB_2147970312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SecoStealer!AMTB"
        threat_id = "2147970312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SecoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SecoStealer.Obfuscation" ascii //weight: 1
        $x_1_2 = "Heaven Stealer" ascii //weight: 1
        $x_1_3 = "SecoStealer.DataSender" ascii //weight: 1
        $x_1_4 = "secokey" ascii //weight: 1
        $x_1_5 = "STOLEN DATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

