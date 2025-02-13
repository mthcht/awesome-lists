rule Trojan_Win32_Milum_2147752351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Milum!MSR"
        threat_id = "2147752351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Milum"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cnf.dat" ascii //weight: 1
        $x_1_2 = "From AntiVirusProduct WHERE displayName <>'Windows Defender" wide //weight: 1
        $x_1_3 = "C:\\ProgramData\\Micapp\\Windows" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_5 = "Milum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

