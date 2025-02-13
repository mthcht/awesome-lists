rule HackTool_Win32_Prontofy_A_2147838290_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Prontofy.A!dha"
        threat_id = "2147838290"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Prontofy"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FakeIUnknown" ascii //weight: 1
        $x_1_2 = "TryAddTokenPriv" ascii //weight: 1
        $x_1_3 = "fakeIUnknownPtr" ascii //weight: 1
        $x_1_4 = "fakeIUnknownVtblPtr" ascii //weight: 1
        $x_1_5 = "TryTakeToken" ascii //weight: 1
        $x_1_6 = "createProcessReadOut" ascii //weight: 1
        $x_1_7 = "createProcessInteractive" ascii //weight: 1
        $x_1_8 = "WindowsImpersonationContext" ascii //weight: 1
        $x_1_9 = "854A20FB-2D44-457D-992F-EF13785D2B51" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

