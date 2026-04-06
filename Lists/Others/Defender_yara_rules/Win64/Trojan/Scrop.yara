rule Trojan_Win64_Scrop_NP_2147960142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Scrop.NP!MTB"
        threat_id = "2147960142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Scrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 c2 48 8d 45 b0 48 01 d0 66 c7 00 5c 00 8b 85 18 06 00 00 48 98 48 8b 94 c5 d0 04 00 00 48 8d 45 b0 48 89 c1}  //weight: 2, accuracy: High
        $x_1_2 = {48 83 bd b8 08 00 00 00 74 2a 8b 85 b4 08 00 00 48 63 d0 48 8b 8d b8 08 00 00 48 8d 85 b0 00 00 00 49 89 c9 49 89 d0 ba 01 00 00 00 48 89 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Scrop_VGZ_2147966374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Scrop.VGZ!MTB"
        threat_id = "2147966374"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Scrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "K8mN2pQ5rT7vW0xY3zA6bC9dE1fG4hJ2" ascii //weight: 1
        $x_1_2 = "timeout /t 10 /nobreak >nul" ascii //weight: 1
        $x_1_3 = "del /f /q \"" ascii //weight: 1
        $x_1_4 = "start \"\" \"" ascii //weight: 1
        $x_1_5 = "DocumentsAppDataAPPDATAUSERPROFILEcmd.exe/c" ascii //weight: 1
        $x_1_6 = "haagsde1.lnk" ascii //weight: 1
        $x_1_7 = ".bat" ascii //weight: 1
        $x_1_8 = "powershell.exe-ExecutionPolicyBypass-Command" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Windows\\CurrentVersion\\ExplorerLogon" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_11 = "Local\\BotkillerMutex_v1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

