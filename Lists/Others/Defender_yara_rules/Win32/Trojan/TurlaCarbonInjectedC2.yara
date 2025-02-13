rule Trojan_Win32_TurlaCarbonInjectedC2_2147849794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurlaCarbonInjectedC2"
        threat_id = "2147849794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurlaCarbonInjectedC2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to parse beacon response. Error code:" ascii //weight: 1
        $x_1_2 = "Heartbeat failed. Error code:" ascii //weight: 1
        $x_1_3 = "Truncated pipe server log file." ascii //weight: 1
        $x_1_4 = "Successfully uploaded C2 log file." ascii //weight: 1
        $x_1_5 = "Downloaded payload:" ascii //weight: 1
        $x_1_6 = "Discovered computer name:" ascii //weight: 1
        $x_1_7 = "Set implant ID to" ascii //weight: 1
        $x_1_8 = "Received empty intruction. Will forward to executor client." ascii //weight: 1
        $x_1_9 = "Failed to execute task. Error code:" ascii //weight: 1
        $x_1_10 = "checkmateNASA" ascii //weight: 1
        $x_1_11 = "[ERROR] Failed to wait for mutex. Error code: " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

