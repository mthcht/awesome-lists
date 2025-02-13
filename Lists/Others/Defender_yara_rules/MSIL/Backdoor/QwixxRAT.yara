rule Backdoor_MSIL_QwixxRAT_A_2147853220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/QwixxRAT.A!ibt"
        threat_id = "2147853220"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QwixxRAT"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Qwixx Stealler" wide //weight: 10
        $x_2_2 = "t.me/QwixxTwixx" wide //weight: 2
        $x_1_3 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_4 = "SELECT * FROM FirewallProduct" wide //weight: 1
        $x_1_5 = "credit_cards.txt" wide //weight: 1
        $x_1_6 = "/Keylogger" wide //weight: 1
        $x_1_7 = "/GetCreditCards" wide //weight: 1
        $x_1_8 = "/EncryptFileSystem" wide //weight: 1
        $x_1_9 = "\\root\\SecurityCenter2" wide //weight: 1
        $x_1_10 = "/create /f /sc ONLOGON /RL HIGHEST /tn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

