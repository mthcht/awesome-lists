rule Backdoor_MSIL_Agent_C_2147652072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Agent.C"
        threat_id = "2147652072"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 17 06 00 70 1f 21 28 50 00 00 0a 25 72 2b 06 00 70 1f 22 28 50 00 00 0a 25 72 d0 01 00 70 1f 23 28 50 00 00 0a fe 13 80 25 00 00 04 fe 13 7e 25}  //weight: 1, accuracy: High
        $x_1_2 = {02 25 7b 1d 00 00 04 17 59 7d 1d 00 00 04 2a 02 72 3b 0b 00 70 72 d0 01 00 70 28 13 00 00 06 2a}  //weight: 1, accuracy: High
        $x_1_3 = "&receive=upload&uploadtype=ufile&filename=" wide //weight: 1
        $x_1_4 = "beerg.eu/PHP%20Files/bot.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

