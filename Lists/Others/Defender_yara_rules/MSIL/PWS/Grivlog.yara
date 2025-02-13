rule PWS_MSIL_Grivlog_A_2147647741_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Grivlog.A"
        threat_id = "2147647741"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Grivlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Grieve_Logger_Stub" ascii //weight: 1
        $x_1_2 = "KeyboardHook" ascii //weight: 1
        $x_1_3 = "Ret_WinCtrl" ascii //weight: 1
        $x_1_4 = "KillProcesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

