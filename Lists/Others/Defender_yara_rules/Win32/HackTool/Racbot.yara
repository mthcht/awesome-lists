rule HackTool_Win32_Racbot_A_2147692232_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Racbot.A"
        threat_id = "2147692232"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Racbot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[ R.A.C ] Bot Generator" ascii //weight: 1
        $x_1_2 = "[ R.A.C ] (Remote Aim Control) Server Builder" ascii //weight: 1
        $x_1_3 = "CmdBots" ascii //weight: 1
        $x_1_4 = "AimPass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

