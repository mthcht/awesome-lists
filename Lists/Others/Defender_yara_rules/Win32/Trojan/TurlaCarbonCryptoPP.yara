rule Trojan_Win32_TurlaCarbonCryptoPP_2147849686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonCryptoPP"
        threat_id = "2147849686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonCryptoPP"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "N8CryptoPP12CAST128_InfoE" ascii //weight: 1
        $x_1_2 = "%p not found?!?!" ascii //weight: 1
        $x_1_3 = "T%p %d V=%0X H=%p %s" ascii //weight: 1
        $x_1_4 = "[TASK] Outputting to send file:" ascii //weight: 1
        $x_1_5 = "[TASK] Comms lib active, performing tasking checks" ascii //weight: 1
        $x_1_6 = "[TASK] Attempting to get ownership of mutex:" ascii //weight: 1
        $x_1_7 = "C:\\Program Files\\Windows NT\\history.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

