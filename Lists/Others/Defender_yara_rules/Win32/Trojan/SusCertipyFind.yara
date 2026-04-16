rule Trojan_Win32_SusCertipyFind_AM_2147967127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusCertipyFind.AM"
        threat_id = "2147967127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusCertipyFind"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certipy" wide //weight: 1
        $x_1_2 = " find " wide //weight: 1
        $x_1_3 = "-vulnerable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

