rule Trojan_Win32_UrlRepE2ETest_A_2147749813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrlRepE2ETest.A"
        threat_id = "2147749813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrlRepE2ETest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "certutil" wide //weight: 10
        $x_90_2 = "https://thiscannotpossiblywork.local/" wide //weight: 90
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

