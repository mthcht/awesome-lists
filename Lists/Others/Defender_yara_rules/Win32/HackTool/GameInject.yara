rule HackTool_Win32_GameInject_A_2147754817_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/GameInject.A!MTB"
        threat_id = "2147754817"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GameInject"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProgramData\\Microsoft\\NiqoVIP.dll" wide //weight: 1
        $x_1_2 = "hack game online" ascii //weight: 1
        $x_1_3 = "Quit After Injections" ascii //weight: 1
        $x_1_4 = "Dll Injected" wide //weight: 1
        $x_1_5 = "frmLogin" ascii //weight: 1
        $x_1_6 = "N3z Hack" ascii //weight: 1
        $x_1_7 = "Desktop\\Inject-Source" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

