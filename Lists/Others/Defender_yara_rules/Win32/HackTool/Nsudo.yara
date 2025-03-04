rule HackTool_Win32_NSudo_A_2147810347_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NSudo.A"
        threat_id = "2147810347"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NSudo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "licensed by Dinkumware" ascii //weight: 1
        $x_1_2 = "https://github.com/M2Team/NSudo" ascii //weight: 1
        $x_1_3 = "NSudo -U: T -P: E cmd" ascii //weight: 1
        $x_1_4 = "NSudo.exe" ascii //weight: 1
        $x_1_5 = "NSudo.Launcher" ascii //weight: 1
        $x_1_6 = "NSudo.RunAs.TrustedInstaller" ascii //weight: 1
        $x_1_7 = "NSudo.RunAs.System.EnableAllPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

