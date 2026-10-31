rule Trojan_Win64_UACBypassExp_A_2147782176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypassExp.A!MTB"
        threat_id = "2147782176"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii //weight: 1
        $x_1_2 = "Elevation:Administrator!new:" ascii //weight: 1
        $x_1_3 = "explorer.exe" ascii //weight: 1
        $x_1_4 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration" ascii //weight: 1
        $x_1_6 = "{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}" ascii //weight: 1
        $x_1_7 = "cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_UACBypassExp_PADS_2147904397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypassExp.PADS!MTB"
        threat_id = "2147904397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 1d 38 70 e0 41 f7 e8 41 03 d0 c1 fa 06 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 49 41 0f b6 c0 2a c1 04 57 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 11 7c cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_UACBypassExp_AYA_2147929766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypassExp.AYA!MTB"
        threat_id = "2147929766"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "source\\repos\\uacbypps\\x64\\Release\\uacbypps.pdb" ascii //weight: 3
        $x_1_2 = "Software\\Classes\\ms-settings\\Shell\\Open\\command" wide //weight: 1
        $x_1_3 = "EncryptedCommand" wide //weight: 1
        $x_1_4 = "DelegateExecute" wide //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "Windows\\System32\\fodhelper.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_UACBypassExp_NU_2147966730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypassExp.NU!MTB"
        threat_id = "2147966730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ActivatePEBHiding" ascii //weight: 2
        $x_2_2 = "handleUACBypass" ascii //weight: 2
        $x_1_3 = "Keylogger" ascii //weight: 1
        $x_1_4 = "handleKeylogDump" ascii //weight: 1
        $x_1_5 = "ExecuteCMD" ascii //weight: 1
        $x_1_6 = "GetActiveHooks" ascii //weight: 1
        $x_1_7 = "tokenDuplicationAttack" ascii //weight: 1
        $x_1_8 = "scheduleTaskAttack" ascii //weight: 1
        $x_1_9 = "EnsurePersistence" ascii //weight: 1
        $x_1_10 = "ImpersonateSelf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_UACBypassExp_NE_2147979691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypassExp.NE!MTB"
        threat_id = "2147979691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Stop code: CRITICAL_PROCESS_DIED" wide //weight: 2
        $x_2_2 = "Bye Bye Windows" wide //weight: 2
        $x_2_3 = "Windows\\System32 FUCKED" wide //weight: 2
        $x_2_4 = "bcdedit /delete" wide //weight: 2
        $x_2_5 = "YOU GOT FUCKED BY BULLET" wide //weight: 2
        $x_1_6 = "Your PC ran into a problem and needs to restart" wide //weight: 1
        $x_2_7 = "payload_json" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_UACBypassExp_PAHU_2147979805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypassExp.PAHU!MTB"
        threat_id = "2147979805"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 0f b6 d0 42 0f b6 44 15 e0 42 88 44 0d e0 42 88 54 15 e0 42 0f b6 4c 0d e0 48 03 ca 0f b6 c1 0f b6 4c 05 e0 41 30 48 ff 49 83 eb 01 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_UACBypassExp_NR_2147981268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/UACBypassExp.NR!MTB"
        threat_id = "2147981268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypassExp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true" ascii //weight: 1
        $x_1_2 = "User Data\\Default\\Login Data" ascii //weight: 1
        $x_2_3 = "keylogger started" ascii //weight: 2
        $x_2_4 = "rat_" ascii //weight: 2
        $x_1_5 = "steal_cookies" ascii //weight: 1
        $x_1_6 = "kill_defender" ascii //weight: 1
        $x_2_7 = "uac_bypass" ascii //weight: 2
        $x_1_8 = "[encrypted" ascii //weight: 1
        $x_1_9 = "persisted" ascii //weight: 1
        $x_1_10 = "inject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

