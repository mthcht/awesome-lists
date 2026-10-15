rule TrojanDropper_Win64_Sloader_GB_2147980325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Sloader.GB!MTB"
        threat_id = "2147980325"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Sloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xmrig.exe" ascii //weight: 1
        $x_1_2 = "schtasks.exe" ascii //weight: 1
        $x_1_3 = "WindowsCache.vbs" ascii //weight: 1
        $x_1_4 = "WindowsUpdate.vbs" ascii //weight: 1
        $x_1_5 = "miner.exe" ascii //weight: 1
        $x_1_6 = "MNR_DEFAULT" ascii //weight: 1
        $x_1_7 = "MicrosoftCacheAssistant.exe" ascii //weight: 1
        $x_1_8 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_9 = "\\\" --mnr-task" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

