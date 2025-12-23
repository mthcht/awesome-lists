rule Trojan_Win64_Vimditator_SS_2147959955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vimditator.SS!MTB"
        threat_id = "2147959955"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.InstallPersistence" ascii //weight: 1
        $x_1_2 = "main.RemovePersistence" ascii //weight: 1
        $x_1_3 = "main.NewResilientExecutor" ascii //weight: 1
        $x_1_4 = "main.(*TaskExecutor).executePersistence" ascii //weight: 1
        $x_1_5 = "syscall.(*LazyDLL).NewProc" ascii //weight: 1
        $x_1_6 = "main.pkcs7Pad" ascii //weight: 1
        $x_1_7 = "main.(*TaskExecutor).executeCleanup" ascii //weight: 1
        $x_1_8 = "main.NewTaskExecutor" ascii //weight: 1
        $x_1_9 = "main.(*ResilientExecutor).GetCurrentURL" ascii //weight: 1
        $x_1_10 = "main.(*TaskExecutor).executeShell" ascii //weight: 1
        $x_1_11 = "main.(*ConnectionManager).GetSleepDuration" ascii //weight: 1
        $x_1_12 = "main.deriveKey" ascii //weight: 1
        $x_1_13 = "main.getC2URL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

