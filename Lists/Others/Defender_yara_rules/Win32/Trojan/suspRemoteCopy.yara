rule Trojan_Win32_suspRemoteCopy_SA_2147818484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/suspRemoteCopy.SA"
        threat_id = "2147818484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "suspRemoteCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd" wide //weight: 1
        $x_1_2 = " copy " wide //weight: 1
        $x_1_3 = "\\windows\\temp\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

