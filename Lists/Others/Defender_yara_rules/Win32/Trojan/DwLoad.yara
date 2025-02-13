rule Trojan_Win32_DwLoad_2147679525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DwLoad"
        threat_id = "2147679525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DwLoad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UpdJob" wide //weight: 1
        $x_1_2 = "Start Menu\\Programs\\Startup" wide //weight: 1
        $x_1_3 = "{ADMIN}" wide //weight: 1
        $x_1_4 = "{GUEST}" wide //weight: 1
        $x_1_5 = "ActiveTimeBias" wide //weight: 1
        $x_1_6 = "%s\\%s%x%x.tmp" wide //weight: 1
        $x_1_7 = "Starting upgrade!" wide //weight: 1
        $x_1_8 = "http://%S" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

