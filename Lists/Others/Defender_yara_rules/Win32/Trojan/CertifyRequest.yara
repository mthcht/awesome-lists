rule Trojan_Win32_CertifyRequest_AM_2147967133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CertifyRequest.AM"
        threat_id = "2147967133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CertifyRequest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certify" wide //weight: 1
        $x_1_2 = "request" wide //weight: 1
        $x_1_3 = "/template:" wide //weight: 1
        $x_1_4 = "/altname:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CertifyRequest_MK_2147967134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CertifyRequest.MK"
        threat_id = "2147967134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CertifyRequest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certify" wide //weight: 1
        $x_1_2 = "request" wide //weight: 1
        $x_1_3 = "template" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

