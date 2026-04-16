rule Trojan_Win32_SusCertipyAuth_AM_2147967126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusCertipyAuth.AM"
        threat_id = "2147967126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusCertipyAuth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certipy" wide //weight: 1
        $x_1_2 = " auth " wide //weight: 1
        $x_1_3 = "-pfx " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

