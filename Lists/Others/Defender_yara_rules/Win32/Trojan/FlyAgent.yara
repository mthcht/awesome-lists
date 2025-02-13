rule Trojan_Win32_FlyAgent_B_2147630904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyAgent.B"
        threat_id = "2147630904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyAgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 25 41 25 25 00 62 6f 64 79 00 69 6e 6e 65 72 48 54 4d 4c 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 61 33 2e 69 6e 69 00 6e 00 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {14 00 00 00 50 ff 75 f4 e8 ?? ?? ?? ?? 83 c4 08 83 f8 00 b8 00 00 00 00 0f 94 c0 89 45 f0 8b 5d f4 85 db 74 09 53 e8 ?? ?? ?? ?? 83 c4 04 83 7d f0 00 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyAgent_RG_2147845247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyAgent.RG!MTB"
        threat_id = "2147845247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft\\VBS3.vbs" ascii //weight: 1
        $x_1_2 = "Microsoft\\svchcst.exe" ascii //weight: 1
        $x_1_3 = "Microsoft\\Config.ini" ascii //weight: 1
        $x_1_4 = "cmd.exe /c del svchcst.exe" ascii //weight: 1
        $x_1_5 = "Start Menu\\Programs\\Startup\\wins.lnk" ascii //weight: 1
        $x_1_6 = "CurrentVersion\\Run\\360safo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FlyAgent_GMF_2147892106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FlyAgent.GMF!MTB"
        threat_id = "2147892106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FlyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 04 01 00 00 56 53 ff 15 ?? ?? ?? ?? a1 ?? ca 56 00 89 35 ?? 93 56 00 8b fe 38 18 ?? ?? 8b f8 8d 45 f8 50 8d 45 fc}  //weight: 10, accuracy: Low
        $x_1_2 = "\\Windows\\CurrentVersion\\Run\\360sofe" ascii //weight: 1
        $x_1_3 = "@Microsoft\\Config.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

