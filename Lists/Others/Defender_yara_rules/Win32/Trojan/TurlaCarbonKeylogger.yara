rule Trojan_Win32_TurlaCarbonKeylogger_2147849684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonKeylogger"
        threat_id = "2147849684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonKeylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[CTRL+BREAK PROCESSING]" ascii //weight: 1
        $x_1_2 = "[IME JUNJA MODE]" ascii //weight: 1
        $x_1_3 = "Failed to created process with duplicated token. Error code: " ascii //weight: 1
        $x_1_4 = "Set hooks" ascii //weight: 1
        $x_1_5 = "Error getting temp path:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

