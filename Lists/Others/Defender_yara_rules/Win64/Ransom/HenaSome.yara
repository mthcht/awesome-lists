rule Ransom_Win64_HenaSome_LVK_2147970191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HenaSome.LVK!MTB"
        threat_id = "2147970191"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HenaSome"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic shadowcopy delete /nointeractive" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore\" /v DisableConfig /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_4 = "REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore\" /v DisableSR /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_5 = "schtasks /delete /tn \"\\Microsoft\\Windows\\RecoveryEnvironment\\VerifyWinRE" ascii //weight: 1
        $x_1_6 = "schtasks /delete /tn \"\\Microsoft\\Windows\\WindowsBackup\\AutomaticBackup" ascii //weight: 1
        $x_1_7 = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_8 = "bootmgfw.efi" ascii //weight: 1
        $x_1_9 = "\\Start Menu\\Programs\\Startup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

