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

