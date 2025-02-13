rule Worm_Win32_Bugbear_2147626662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bugbear.gen"
        threat_id = "2147626662"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bugbear"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylogdll.dll" ascii //weight: 1
        $x_1_2 = "Labs\\ZoneAlarm\\ZoneAlarm.exe" ascii //weight: 1
        $x_1_3 = "Zabcdefghijklmnopqrstuvwxyz0123456789+/" ascii //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "MAIL FROM:<%s>" ascii //weight: 1
        $x_1_6 = "RCPT TO:<%s>" ascii //weight: 1
        $x_1_7 = "bugbear" ascii //weight: 1
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_9 = "X-Mailer: Microsoft Outlook Express 6.00.2600.0000" ascii //weight: 1
        $x_1_10 = "ControlSet\\Services\\Tcpip\\Parameters" ascii //weight: 1
        $x_1_11 = "Subject: Hello!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

