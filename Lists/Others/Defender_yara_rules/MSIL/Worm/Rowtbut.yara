rule Worm_MSIL_Rowtbut_A_2147636714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Rowtbut.A"
        threat_id = "2147636714"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rowtbut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot.php?hwid=" wide //weight: 1
        $x_1_2 = {42 6f 74 41 6e 74 77 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 53 42 53 70 72 65 61 64 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 74 61 72 74 48 54 54 50 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 74 61 72 74 49 43 4d 50 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 74 61 72 74 53 59 4e 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_MSIL_Rowtbut_B_2147638389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Rowtbut.B"
        threat_id = "2147638389"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rowtbut"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BotAntwort" ascii //weight: 1
        $x_1_2 = "BotBeenden" ascii //weight: 1
        $x_1_3 = "MSNSpreadStart" ascii //weight: 1
        $x_1_4 = "StartHTTPFlood" ascii //weight: 1
        $x_1_5 = "StartICMPFlood" ascii //weight: 1
        $x_1_6 = "StartSYNFlood" ascii //weight: 1
        $x_1_7 = "Bereit!" wide //weight: 1
        $x_1_8 = "?action=reply&hwid=" wide //weight: 1
        $x_1_9 = "?action=getcomm&hwid=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

