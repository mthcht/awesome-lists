rule TrojanDropper_Win32_Phorpiex_AYA_2147929765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Phorpiex.AYA!MTB"
        threat_id = "2147929765"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Phorpiex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VolDriver.exe" wide //weight: 2
        $x_1_2 = "winupsvc.exe" wide //weight: 1
        $x_1_3 = "Documents and Settings\\Administrator\\nodescfg.dat" wide //weight: 1
        $x_1_4 = "Documents and Settings\\Administrator\\cmdcfg.dat" wide //weight: 1
        $x_1_5 = "Unnamed volume (8GB).lnk" wide //weight: 1
        $x_1_6 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_7 = "AntiVirusDisableNotify" ascii //weight: 1
        $x_1_8 = "UpdatesDisableNotify" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

