rule Trojan_Win32_RubeusPKINIT_AM_2147967139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RubeusPKINIT.AM"
        threat_id = "2147967139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RubeusPKINIT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rubeus" wide //weight: 1
        $x_1_2 = "asktgt" wide //weight: 1
        $x_1_3 = "/certificate:" wide //weight: 1
        $x_1_4 = "/ptt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

