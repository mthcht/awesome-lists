rule Ransom_Win64_BallerWare_ABWR_2147969212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BallerWare.ABWR!MTB"
        threat_id = "2147969212"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BallerWare"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell Set-MpPreference -DisableRealtimeMonitoring $true 2>nul" ascii //weight: 1
        $x_1_2 = "Your files got encrypted by BallerWare. Pay up or lose everything" ascii //weight: 1
        $x_1_3 = "powershell Set-MpPreference -DisableIOAVProtection $true 2>nul" ascii //weight: 1
        $x_1_4 = "DO NOT attempt manual decryption (BallerWare will detect)" ascii //weight: 1
        $x_1_5 = "All files encrypted by BallerWare with AES-256" ascii //weight: 1
        $x_1_6 = "Network credentials harvested by BallerWare" ascii //weight: 1
        $x_1_7 = "vssadmin delete shadows /all /quiet 2>nul" ascii //weight: 1
        $x_1_8 = "ballerware_recovery@protonmail.ch" ascii //weight: 1
        $x_1_9 = "You should have paid BallerWare" ascii //weight: 1
        $x_1_10 = "BALLERWARE_READ_NOW.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

