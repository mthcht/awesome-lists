rule Ransom_Win32_Genavm_ARC_2147757621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Genavm.ARC!MSR"
        threat_id = "2147757621"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Genavm"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomware" ascii //weight: 1
        $x_1_2 = "Startup\\StartupFile.exe" wide //weight: 1
        $x_1_3 = "StopAntiService" wide //weight: 1
        $x_1_4 = "KillAntiService" wide //weight: 1
        $x_1_5 = "FirewallDisableNotify" wide //weight: 1
        $x_1_6 = "AntiVirusDisableNotify" wide //weight: 1
        $x_1_7 = "AntiVM" wide //weight: 1
        $x_1_8 = "StealFileInfo" wide //weight: 1
        $x_1_9 = "http://149.20.4.69:21" wide //weight: 1
        $x_1_10 = "qwertyuiopasdfghjkl1234567890" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

