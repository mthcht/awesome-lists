rule Trojan_Win32_DropperAgent_PA_2147752181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DropperAgent.PA!MTB"
        threat_id = "2147752181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DropperAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v disabletaskmgr /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_2 = "reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_1_3 = "reg.exe ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop /v NoChangingWallPaper /t REG_DWORD /d 1 /f" ascii //weight: 1
        $x_1_4 = "reg.exe ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v CheckForUpdates /t REG_SZ /d %homedrive%\\COVID-19\\Update.vbs /f" ascii //weight: 1
        $x_1_5 = "reg.exe ADD HKLM\\software\\Microsoft\\Windows\\CurrentVersion\\Run /v GoodbyePC! /t REG_SZ /d %homedrive%\\COVID-19\\end.exe /f" ascii //weight: 1
        $x_1_6 = "your computer has infected by coronavirus" wide //weight: 1
        $x_1_7 = "Your Computer Has Been Trashed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

