rule Trojan_Win32_SloppyRAT_2147982330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SloppyRAT!atmn"
        threat_id = "2147982330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SloppyRAT"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "copy /y \"%~f0\" \"C:\\Windows\\System32\\conhost.exe\"" ascii //weight: 3
        $x_2_2 = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WinHost1\" /t REG_SZ /d \"C:\\Windows\\System32\\conhost.exe\" /f" ascii //weight: 2
        $x_2_3 = "schtasks /create /sc minute /mo 5 /tn \"WindowsConsoleUpdate\" /tr \"C:\\Windows\\System32\\conhost.exe\" /ru \"SYSTEM\" /f" ascii //weight: 2
        $x_3_4 = "vssadmin delete shadows /all /quiet" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

