rule Trojan_Win32_CertipyAccount_AM_2147967128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CertipyAccount.AM"
        threat_id = "2147967128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CertipyAccount"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certipy" wide //weight: 1
        $x_1_2 = " account " wide //weight: 1
        $x_1_3 = "-hashes" wide //weight: 1
        $x_1_4 = "-user " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

