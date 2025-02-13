rule HackTool_Win32_SysInject_A_2147756961_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SysInject.A!MTB"
        threat_id = "2147756961"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SysInject"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "System Injecktion32 - PointBlank.exe" wide //weight: 1
        $x_1_2 = "Kuteng07.dll" wide //weight: 1
        $x_1_3 = "riki.blitz" wide //weight: 1
        $x_1_4 = "invisible" wide //weight: 1
        $x_1_5 = "NotHackerKiee.Blogspot.Com" ascii //weight: 1
        $x_1_6 = {52 00 69 00 6b 00 69 00 42 00 4c 00 69 00 54 00 7a 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

