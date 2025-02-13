rule Trojan_Win32_MpTamperSrvStop_A_2147829956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperSrvStop.A"
        threat_id = "2147829956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperSrvStop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sense" wide //weight: 1
        $x_1_2 = "wdnissvc" wide //weight: 1
        $x_1_3 = "windefend" wide //weight: 1
        $x_10_4 = "-dcsvc" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

