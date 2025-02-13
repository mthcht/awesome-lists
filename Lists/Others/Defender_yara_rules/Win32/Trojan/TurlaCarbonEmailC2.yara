rule Trojan_Win32_TurlaCarbonEmailC2_2147849791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonEmailC2"
        threat_id = "2147849791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonEmailC2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "filename=\"confirmation_icon.jpeg\"" ascii //weight: 1
        $x_1_2 = "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Bin\\winmail.dat" ascii //weight: 1
        $x_1_3 = "EMAIL_LOG_FILE" ascii //weight: 1
        $x_1_4 = "Successfully deleted file:" ascii //weight: 1
        $x_1_5 = "Could not delete email log file." ascii //weight: 1
        $x_1_6 = "Execute a command line" ascii //weight: 1
        $x_1_7 = "Procesing container" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

