rule Trojan_Win32_Mades_A_2147598842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mades.A"
        threat_id = "2147598842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mades"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetOpenA" ascii //weight: 1
        $x_1_2 = "\\mssecc.exe" ascii //weight: 1
        $x_1_3 = "%s%08x.exe" ascii //weight: 1
        $x_1_4 = "%s /c del %s >>NUL" ascii //weight: 1
        $x_1_5 = "http://www.malwaredestructor.com/download.php?aid=" ascii //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

