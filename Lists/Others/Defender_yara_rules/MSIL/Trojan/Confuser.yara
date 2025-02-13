rule Trojan_MSIL_Confuser_UI_2147734918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Confuser.UI"
        threat_id = "2147734918"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Confuser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitcoinStealer.exe" ascii //weight: 1
        $x_1_2 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_3 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

