rule Backdoor_Win32_Subseven_H_2147792441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Subseven.H"
        threat_id = "2147792441"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Subseven"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\System" ascii //weight: 1
        $x_2_2 = "Error Recovering Passwords" ascii //weight: 2
        $x_3_3 = "SubSeven Server is running" ascii //weight: 3
        $x_6_4 = "Sub7 2.3 2010" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

