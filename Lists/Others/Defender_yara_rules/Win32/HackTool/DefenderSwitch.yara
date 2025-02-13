rule HackTool_Win32_DefenderSwitch_A_2147812077_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DefenderSwitch.A"
        threat_id = "2147812077"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DefenderSwitch"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DefenderSwitch.pdb" ascii //weight: 1
        $x_1_2 = "Couldn't stop WinDefend service" ascii //weight: 1
        $x_1_3 = "Trying to stop Windows Defender" ascii //weight: 1
        $x_1_4 = "Usage: .\\DefenderSwitch.exe [-on|-off]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

