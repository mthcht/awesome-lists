rule Trojan_Win32_CertifyManageTemplate_AM_2147967137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CertifyManageTemplate.AM"
        threat_id = "2147967137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CertifyManageTemplate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certify" wide //weight: 1
        $x_1_2 = "manage-template" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

