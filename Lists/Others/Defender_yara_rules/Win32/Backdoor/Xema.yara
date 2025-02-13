rule Backdoor_Win32_Xema_A_2147576653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xema.gen!A"
        threat_id = "2147576653"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xema"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "401"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {ba 01 00 00 80 8b ?? e8 ?? ?? ?? ff b1 01 ba ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ff b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b}  //weight: 100, accuracy: Low
        $x_100_2 = {ba 02 00 00 80 8b ?? e8 ?? ?? ?? ff b1 01 ba ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ff b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b}  //weight: 100, accuracy: Low
        $x_1_3 = "CopyFileA" ascii //weight: 1
        $x_100_4 = "C:\\Program Files\\Internet Explorer\\syssmss.exe" ascii //weight: 100
        $x_100_5 = "c:\\windows\\system32\\com\\con\\winserv\\winserv.exe" ascii //weight: 100
        $x_100_6 = "C:\\WINDOWS\\System32\\system32.exe" ascii //weight: 100
        $x_100_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 100
        $x_100_8 = "WinsSystem" ascii //weight: 100
        $x_100_9 = "winservu" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_1_*))) or
            ((5 of ($x_100_*))) or
            (all of ($x*))
        )
}

