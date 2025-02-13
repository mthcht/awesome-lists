rule Trojan_Win32_MKLKlog_A_2147611280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MKLKlog.A"
        threat_id = "2147611280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MKLKlog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "M.K.L." ascii //weight: 1
        $x_1_2 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_3 = "netsh.exe firewall add allowedprogram %s WinFirewall" ascii //weight: 1
        $x_1_4 = "LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32" ascii //weight: 1
        $x_1_5 = "gsmtp185.google.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

