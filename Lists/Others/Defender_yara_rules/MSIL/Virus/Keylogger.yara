rule Virus_MSIL_Keylogger_A_2147687549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:MSIL/Keylogger.A"
        threat_id = "2147687549"
        type = "Virus"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StartKeyLogger" ascii //weight: 1
        $x_1_2 = "StartReplicationService" ascii //weight: 1
        $x_1_3 = "SendMail" ascii //weight: 1
        $x_1_4 = "InfectEXE" ascii //weight: 1
        $x_1_5 = "DetectRemovableDrive" ascii //weight: 1
        $x_1_6 = "<-print screen->" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

