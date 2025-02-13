rule Trojan_Win32_OfficeAppMshta_A_2147757526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OfficeAppMshta.A"
        threat_id = "2147757526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OfficeAppMshta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = "vbscript" wide //weight: 10
        $x_10_3 = "execute" wide //weight: 10
        $x_10_4 = "textrange" wide //weight: 10
        $x_10_5 = "word.application" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

