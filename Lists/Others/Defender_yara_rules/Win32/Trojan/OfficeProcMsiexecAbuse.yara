rule Trojan_Win32_OfficeProcMsiexecAbuse_A_2147735550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OfficeProcMsiexecAbuse.A"
        threat_id = "2147735550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OfficeProcMsiexecAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-48] 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

