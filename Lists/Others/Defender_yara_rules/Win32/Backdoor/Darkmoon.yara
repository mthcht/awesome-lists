rule Backdoor_Win32_Darkmoon_AE_2147792185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Darkmoon.AE"
        threat_id = "2147792185"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkmoon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "72"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "stop sharedaccess" ascii //weight: 10
        $x_10_3 = {00 6e 65 74 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_4 = "DarkMoon" ascii //weight: 10
        $x_10_5 = "mail from:" ascii //weight: 10
        $x_10_6 = "{BACK}" ascii //weight: 10
        $x_10_7 = "CyberNetic" ascii //weight: 10
        $x_1_8 = "Microsoft MSN" ascii //weight: 1
        $x_1_9 = "HOLA@hotmail.com" ascii //weight: 1
        $x_1_10 = "StArTLiStFM" ascii //weight: 1
        $x_1_11 = "subject: testing" ascii //weight: 1
        $x_1_12 = "procedeServerCMD" ascii //weight: 1
        $x_1_13 = "DmPaSsWrOnG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Darkmoon_MR_2147792478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Darkmoon.MR!MTB"
        threat_id = "2147792478"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 5b 03 d8 89 5d ?? 8b 5d ?? 8a 03 8b 5d ?? 88 03 58 5b 59 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\LmHosts" ascii //weight: 1
        $x_1_3 = "BlackMoon RunTime Error:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Darkmoon_DA_2147792479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Darkmoon.DA!MTB"
        threat_id = "2147792479"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkmoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\fuzhu.dll" ascii //weight: 1
        $x_1_2 = "cmd.exe /c del" ascii //weight: 1
        $x_1_3 = "netsh winsock reset" ascii //weight: 1
        $x_1_4 = "BlackMoon RunTime Error" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

