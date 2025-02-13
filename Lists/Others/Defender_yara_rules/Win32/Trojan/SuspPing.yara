rule Trojan_Win32_SuspPing_A_2147782774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspPing.A"
        threat_id = "2147782774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ping -t 127.0.0.1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

