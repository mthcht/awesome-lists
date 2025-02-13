rule Rogue_MSIL_Toprot_168906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:MSIL/Toprot"
        threat_id = "168906"
        type = "Rogue"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Toprot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "security-shield" wide //weight: 2
        $x_2_2 = "Backdoor:Win32/Cycbot.B is a backdoor trojan that allows attackers unauthorized access and control" wide //weight: 2
        $x_2_3 = "Computer Status - Unprotected! Click here to protect your computer." wide //weight: 2
        $x_2_4 = "/order/pay.php?hwid=" wide //weight: 2
        $x_1_5 = "Activate now to remove threats." wide //weight: 1
        $x_1_6 = "Please Activate your copy of Anti-Virus Pro" wide //weight: 1
        $x_1_7 = "AV.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

