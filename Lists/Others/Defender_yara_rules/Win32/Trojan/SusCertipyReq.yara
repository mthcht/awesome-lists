rule Trojan_Win32_SusCertipyReq_AM_2147967125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusCertipyReq.AM"
        threat_id = "2147967125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusCertipyReq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certipy" wide //weight: 1
        $x_1_2 = " req " wide //weight: 1
        $x_1_3 = "-template " wide //weight: 1
        $x_1_4 = "-upn " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

