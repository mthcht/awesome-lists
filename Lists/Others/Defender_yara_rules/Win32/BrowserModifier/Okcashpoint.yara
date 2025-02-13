rule BrowserModifier_Win32_Okcashpoint_18098_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Okcashpoint"
        threat_id = "18098"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Okcashpoint"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual C++ Runtime Library" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "NaverTOOlbar" ascii //weight: 1
        $x_1_4 = "okcpmgr.exe" ascii //weight: 1
        $x_1_5 = "user.dat" ascii //weight: 1
        $x_1_6 = "reword.cfg" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
        $x_1_8 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Okcashpoint_18098_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Okcashpoint"
        threat_id = "18098"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Okcashpoint"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "ok-cashpoint.com" ascii //weight: 1
        $x_1_4 = "okcpmgr.exe" ascii //weight: 1
        $x_1_5 = "AAA9FE33-528F-48A8-A98B-4991F9D96DDA" ascii //weight: 1
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_7 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Okcashpoint_18098_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Okcashpoint"
        threat_id = "18098"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Okcashpoint"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "ok-cashpoint.com" ascii //weight: 1
        $x_1_4 = "okcpmgr.exe" ascii //weight: 1
        $x_1_5 = "AAA9FE33-528F-48A8-A98B-4991F9D96DDA" ascii //weight: 1
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

