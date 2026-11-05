rule TrojanSpy_Win64_Yogi_SS_2147981544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Yogi.SS!MTB"
        threat_id = "2147981544"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Yogi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.detectFirefoxProfiles" ascii //weight: 1
        $x_1_2 = "main.cookiesHasWhatsApp" ascii //weight: 1
        $x_1_3 = "main.copyFileBackupRead" ascii //weight: 1
        $x_1_4 = "main.copyFileRobocopy" ascii //weight: 1
        $x_1_5 = "main.enableSeBackupPrivilege" ascii //weight: 1
        $x_1_6 = "main.diagReadBrowsers" ascii //weight: 1
        $x_1_7 = "main.runSelfDestruct" ascii //weight: 1
        $x_1_8 = "main.processStillRunning" ascii //weight: 1
        $x_1_9 = "main.diagUpload" ascii //weight: 1
        $x_1_10 = "main.rawAlignedAlloc" ascii //weight: 1
        $x_1_11 = "main.rawAlignedFree" ascii //weight: 1
        $x_1_12 = "main.copyFileRawVolume" ascii //weight: 1
        $x_1_13 = "main.uploadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

