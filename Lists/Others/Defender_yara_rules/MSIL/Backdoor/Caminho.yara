rule Backdoor_MSIL_Caminho_AR_2147964113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Caminho.AR!AMTB"
        threat_id = "2147964113"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Caminho"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "caminhovbs" ascii //weight: 10
        $x_1_2 = "LogonTrigger" ascii //weight: 1
        $x_1_3 = "Microsoft.Win32.TaskScheduler.Properties" ascii //weight: 1
        $x_1_4 = "LazyList" ascii //weight: 1
        $x_1_5 = "DummyLogger" ascii //weight: 1
        $x_1_6 = "CreateInstance" ascii //weight: 1
        $x_1_7 = "Capture" ascii //weight: 1
        $x_1_8 = "set_UserAccountDomain" ascii //weight: 1
        $x_1_9 = "set_UserPassword" ascii //weight: 1
        $x_1_10 = "caminho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

