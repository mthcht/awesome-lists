rule Trojan_Win32_CertifyForge_AM_2147967135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CertifyForge.AM"
        threat_id = "2147967135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CertifyForge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certify" wide //weight: 1
        $x_1_2 = "forge" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

