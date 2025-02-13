rule Backdoor_MSIL_Popiidor_A_2147686760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Popiidor.A"
        threat_id = "2147686760"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Popiidor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "handleDownloadAndExecuteCommand" ascii //weight: 1
        $x_1_2 = "handleDownloadFile" ascii //weight: 1
        $x_1_3 = "handleDrives" ascii //weight: 1
        $x_1_4 = "handleKillProcess" ascii //weight: 1
        $x_1_5 = "handleVisitWebsite" ascii //weight: 1
        $x_1_6 = "handleMouseClick" ascii //weight: 1
        $x_1_7 = "handleRemoteDesktop" ascii //weight: 1
        $x_1_8 = "handleStartProcess" ascii //weight: 1
        $x_1_9 = {53 54 41 52 54 55 50 4b 45 59 00 48 49 44 45 46 49 4c 45 00}  //weight: 1, accuracy: High
        $x_1_10 = {75 72 6c 00 72 75 6e 68 69 64 64 65 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Popiidor_A_2147686760_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Popiidor.A"
        threat_id = "2147686760"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Popiidor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{0} {1} {2} Bit" wide //weight: 1
        $x_1_2 = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "handleDownloadAndExecuteCommand" ascii //weight: 1
        $x_1_5 = "handleKillProcess" ascii //weight: 1
        $x_1_6 = "handleVisitWebsite" ascii //weight: 1
        $x_1_7 = "tryUACTrick" ascii //weight: 1
        $x_1_8 = "$$$EMPTY$$$$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

