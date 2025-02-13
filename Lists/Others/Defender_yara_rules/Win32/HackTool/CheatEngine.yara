rule HackTool_Win32_CheatEngine_RC_2147772782_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CheatEngine.RC!MTB"
        threat_id = "2147772782"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CheatEngine"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHEAT POINTBLANK HARD" ascii //weight: 1
        $x_1_2 = "CHEAT POINTBLANK SIMPLE" ascii //weight: 1
        $x_1_3 = "Hack Error! Please Run As Ulang Atau Restart Komputer Anda" ascii //weight: 1
        $x_1_4 = "Hack successfully! Happy cheating " ascii //weight: 1
        $x_1_5 = "Welcome Cheaters" ascii //weight: 1
        $x_1_6 = "All In One Hacks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

