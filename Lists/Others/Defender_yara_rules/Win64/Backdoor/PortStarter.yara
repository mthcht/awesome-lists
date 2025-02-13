rule Backdoor_Win64_PortStarter_B_2147830160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PortStarter.B"
        threat_id = "2147830160"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PortStarter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Invoke-SocksProxy/main.go" ascii //weight: 1
        $x_1_2 = "-Command \"New-NetFirewallRule -DisplayName 'Windows Update' -Direction Outbound -Action Allow" ascii //weight: 1
        $x_1_3 = "-Command \"%s%s%s%s%sle -DisplayName %s%s%s %s%s -Direction Outbound -Action Allow" ascii //weight: 1
        $x_1_4 = "-Command \"Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty domain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win64_PortStarter_DA_2147840008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PortStarter.DA!MTB"
        threat_id = "2147840008"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PortStarter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 40 08 03 00 00 00 48 8d 0d ?? ?? ?? ?? 48 89 08 48 8d 0d ?? ?? ?? ?? 48 89 48 10 48 c7 40 28 03 00 00 00 48 8d 0d ?? ?? ?? ?? 48 89 48 20 48 8d 0d ?? ?? ?? ?? 48 89 48 30 48 c7 40 48 04 00 00 00 48 8d 0d ?? ?? ?? ?? 48 89 48 40 48 8d 0d ?? ?? ?? ?? 48 89 48 50 48 c7 40 68 09 00 00 00 48 8d 0d ?? ?? ?? ?? 48 89 48 60 48 8d 0d ?? ?? ?? ?? 48 89 48 70 48 c7 80 88 00 00 00 06 00 00 00 48 8d 0d}  //weight: 1, accuracy: Low
        $x_1_2 = "_cgo_dummy_export" ascii //weight: 1
        $x_1_3 = "main.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

