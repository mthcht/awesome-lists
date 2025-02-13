rule Backdoor_MSIL_Horsamaz_B_2147658350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Horsamaz.B"
        threat_id = "2147658350"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Horsamaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MyHorseIsAmazing" wide //weight: 5
        $x_5_2 = "Thisisaproblemfortorva" wide //weight: 5
        $x_1_3 = "Task Manager killed and re-enabled" wide //weight: 1
        $x_1_4 = "Log Sent..." wide //weight: 1
        $x_1_5 = "Screenshot sent..." wide //weight: 1
        $x_1_6 = "KEYLOGGER" wide //weight: 1
        $x_1_7 = "[MUTEX]" wide //weight: 1
        $x_1_8 = "Unable to connect to server" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Horsamaz_A_2147678433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Horsamaz.A"
        threat_id = "2147678433"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Horsamaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MyHorseIsAmazing" wide //weight: 2
        $x_1_2 = "Udp Flood Active..." wide //weight: 1
        $x_1_3 = "All Floods Disabled..." wide //weight: 1
        $x_1_4 = "regClient" wide //weight: 1
        $x_1_5 = "Task Manager killed and re-enabled..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

