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

rule Trojan_Win64_Vimditator_PGVD_2147962587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vimditator.PGVD!MTB"
        threat_id = "2147962587"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vimditator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 85 ff 74 ab 40 30 2c 38 69 ed ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 48 ff c7 eb}  //weight: 3, accuracy: Low
        $x_2_2 = {9e 91 71 34 61 ae 74 5e da 98 d3 8a 09 f0 11 36 e9 46 cb fb e9 14 46 e6 3a bb 39 d4 cc a9 22 e7 c4 e0 49 2f b4 0e 8b e8 52 30 4e 14 41 ed 95 6c bd f1 2c a7 ab}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

