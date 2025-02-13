rule Trojan_Win32_DelayedLogClearing_A_2147814176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelayedLogClearing.A"
        threat_id = "2147814176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelayedLogClearing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ping localhost" wide //weight: 10
        $x_10_2 = "wevtutil cl System" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

