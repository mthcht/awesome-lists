rule BrowserModifier_Win32_Cashbacksys_18103_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Cashbacksys"
        threat_id = "18103"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Cashbacksys"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_2 = "cashback-sysbar.dll" ascii //weight: 1
        $x_1_3 = "cashback-sys_2.dll" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Ext\\Settings\\{5A921613-323F-4906-A026-B7205F3A01EF}" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_6 = "CreateMutexA" ascii //weight: 1
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

