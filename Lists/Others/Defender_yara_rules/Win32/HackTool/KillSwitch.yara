rule HackTool_Win32_KillSwitch_A_2147888242_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KillSwitch.A"
        threat_id = "2147888242"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KillSwitch"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\COMODO_KILLSWITCH_MUTEX" ascii //weight: 1
        $x_1_2 = "COMODO KillSwitch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

