rule Backdoor_MSIL_Boilod_A_2147692463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Boilod.A"
        threat_id = "2147692463"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Boilod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogger" ascii //weight: 1
        $x_1_2 = "Webcam" ascii //weight: 1
        $x_1_3 = "PasswordRecovery" ascii //weight: 1
        $x_1_4 = "StartMiner" ascii //weight: 1
        $x_1_5 = "SendScreen" ascii //weight: 1
        $x_1_6 = "StartScan" ascii //weight: 1
        $x_1_7 = "Spyware" ascii //weight: 1
        $x_1_8 = "dlExecute" ascii //weight: 1
        $x_1_9 = "ShowChat" ascii //weight: 1
        $x_1_10 = "StartProxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

