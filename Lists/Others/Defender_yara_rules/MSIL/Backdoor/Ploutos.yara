rule Backdoor_MSIL_Ploutos_A_2147725175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Ploutos.A!bit"
        threat_id = "2147725175"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ploutos"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_2_2 = "Startup Fucked" wide //weight: 2
        $x_1_3 = "filehelp.us/ip.php" wide //weight: 1
        $x_1_4 = "minerdll.exe" wide //weight: 1
        $x_2_5 = {77 00 68 00 69 00 74 00 65 00 68 00 61 00 74 00 2e 00 73 00 75 00 2f 00 [0-24] 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_6 = "botkill" wide //weight: 2
        $x_1_7 = "slowloris" wide //weight: 1
        $x_1_8 = "tcpflood" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Ploutos_B_2147725176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Ploutos.B!bit"
        threat_id = "2147725176"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ploutos"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MiningTask" ascii //weight: 1
        $x_1_2 = "LoggerTask" ascii //weight: 1
        $x_2_3 = "ProteusHTTPBotnet" ascii //weight: 2
        $x_1_4 = "RegisterBot" ascii //weight: 1
        $x_1_5 = "keyboardHookProc" ascii //weight: 1
        $x_1_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00 4c 6f 61 64 41 6e 64 53 74 61 72 74 46 69 6c 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

