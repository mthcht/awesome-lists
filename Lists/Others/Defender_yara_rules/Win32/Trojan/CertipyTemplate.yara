rule Trojan_Win32_CertipyTemplate_AM_2147967129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CertipyTemplate.AM"
        threat_id = "2147967129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CertipyTemplate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certipy" wide //weight: 1
        $x_1_2 = " template " wide //weight: 1
        $x_1_3 = "-save-old" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CertipyTemplate_MK_2147967130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CertipyTemplate.MK"
        threat_id = "2147967130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CertipyTemplate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certipy" wide //weight: 1
        $x_1_2 = " template " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

