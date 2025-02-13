rule Backdoor_MSIL_Sorcas_A_2147728362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Sorcas.A"
        threat_id = "2147728362"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sorcas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Sorgu.exe" ascii //weight: 10
        $x_10_2 = "set_AutoLog" ascii //weight: 10
        $x_10_3 = "DownloadString" ascii //weight: 10
        $x_10_4 = "EmptyWorkingSet" ascii //weight: 10
        $x_10_5 = "x509Chain_0" ascii //weight: 10
        $x_10_6 = "CmdService" ascii //weight: 10
        $x_10_7 = "RunCmd" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

