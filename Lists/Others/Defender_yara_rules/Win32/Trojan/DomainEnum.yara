rule Trojan_Win32_DomainEnum_ZZZ_2147944597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DomainEnum.ZZZ!MTB"
        threat_id = "2147944597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DomainEnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "domain users" wide //weight: 1
        $x_1_2 = "/domain >" wide //weight: 1
        $x_1_3 = {74 00 65 00 6d 00 70 00 [0-60] 2e 00 74 00 6d 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

