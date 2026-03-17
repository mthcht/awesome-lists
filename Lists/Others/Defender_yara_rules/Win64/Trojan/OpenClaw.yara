rule Trojan_Win64_OpenClaw_GY_2147964927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OpenClaw.GY!MTB"
        threat_id = "2147964927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OpenClaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fetching archive password from server." ascii //weight: 1
        $x_1_2 = "Trying primary URL" ascii //weight: 1
        $x_1_3 = "Virtual GPU detected:" ascii //weight: 1
        $x_1_4 = "Bot farm hostname pattern '' matches " ascii //weight: 1
        $x_1_5 = "Suspicious: Blacklisted BIOS serial detected:" ascii //weight: 1
        $x_1_6 = "powershell.exe-NoProfile-NonInteractive-WindowStyleHidden-ExecutionPolicyBypass-EncodedCommandWMI" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\PathsRegistry access denied:" ascii //weight: 1
        $x_1_8 = "Automatic hardware driver update tool" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

