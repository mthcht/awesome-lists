rule Trojan_Win32_ProcessSearchOrderHijack_A_2147949428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessSearchOrderHijack.A"
        threat_id = "2147949428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessSearchOrderHijack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whoami" wide //weight: 1
        $x_1_2 = "help" wide //weight: 1
        $x_1_3 = "ipconfig" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

