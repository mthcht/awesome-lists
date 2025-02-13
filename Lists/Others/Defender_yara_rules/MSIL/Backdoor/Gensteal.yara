rule Backdoor_MSIL_Gensteal_A_2147688972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Gensteal.A"
        threat_id = "2147688972"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gensteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/CMDCMDGO/" wide //weight: 1
        $x_1_2 = "/PSWRECOV/" wide //weight: 1
        $x_1_3 = "/WEBCAPTR/" wide //weight: 1
        $x_1_4 = "/LISTPROC/" wide //weight: 1
        $x_1_5 = "/REGVIEWV/" wide //weight: 1
        $x_1_6 = "/PAKSSEND/" wide //weight: 1
        $x_1_7 = "/SOUNDREC/" wide //weight: 1
        $x_1_8 = "/INFOPCPC/" wide //weight: 1
        $x_1_9 = "/KEYSLOGG/" wide //weight: 1
        $x_1_10 = "/STARTSQL/" wide //weight: 1
        $x_1_11 = "/DOWNFILE/" wide //weight: 1
        $x_1_12 = "/UPLOADFL/" wide //weight: 1
        $x_1_13 = "/RUNEXEFL/" wide //weight: 1
        $x_1_14 = "/SCRSTART/" wide //weight: 1
        $x_1_15 = "/STRTSERV/" wide //weight: 1
        $x_1_16 = "/AUTOSERV/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

