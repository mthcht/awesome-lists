rule Trojan_Win64_NjRat_NEBG_2147838654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NjRat.NEBG!MTB"
        threat_id = "2147838654"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 41 96 30 44 0c ?? 48 ff c1 48 83 f9 ?? 72 f0 c6}  //weight: 10, accuracy: Low
        $x_1_2 = "71.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NjRat_AB_2147965797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NjRat.AB!MTB"
        threat_id = "2147965797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {57 56 48 83 ec 38 48 8d 35 e3 2c 00 00 31 c0 48 8d 7c 24 0f 49 89 c8 b9 21 00 00 00 f3 a4 48 39 d0 74 13 48 89 c1 83 e1 1f 8a 4c 0c 0f 41 30 0c 00 48 ff c0 eb e8}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NjRat_ARR_2147967500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NjRat.ARR!MTB"
        threat_id = "2147967500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NjRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet' /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f" ascii //weight: 4
        $x_8_2 = "reg add 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet' /v SpynetReporting /t REG_DWORD /d 0 /f" ascii //weight: 8
        $x_5_3 = "reg add 'HKCU\\Software\\Policies\\Microsoft\\Windows\\Explorer' /v DisableNotificationCenter /t REG_DWORD /d 1 /f" ascii //weight: 5
        $x_3_4 = "reg add 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications' /v ToastEnabled /t REG_DWORD /d 0 /f" ascii //weight: 3
        $x_10_5 = "powershell.exe -Command \"Set-MpPreference -DisableRealtimeMonitoring $true" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

