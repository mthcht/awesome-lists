rule Trojan_Win32_Remetrac_C_2147621169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remetrac.C"
        threat_id = "2147621169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remetrac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DelayTime" ascii //weight: 1
        $x_1_2 = "HostsUrls" ascii //weight: 1
        $x_2_3 = {68 ef cd 00 00 68 dc fe 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {05 0f 27 00 00 39 45 fc 72 bc 6a 00}  //weight: 2, accuracy: High
        $x_1_5 = {31 ff eb 15 a0 ?? ?? ?? ?? 38 04 1f 75 0a c6 04 1f 00 8d 5c 1f 01 eb 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

