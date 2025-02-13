rule Trojan_MSIL_Soraccaunt_A_2147728355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Soraccaunt.A"
        threat_id = "2147728355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Soraccaunt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CheckAccount.exe" ascii //weight: 10
        $x_10_2 = "Check Passwords" wide //weight: 10
        $x_10_3 = "exchange.asmx" wide //weight: 10
        $x_10_4 = "mailbox" wide //weight: 10
        $x_10_5 = "Check Usernames" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

