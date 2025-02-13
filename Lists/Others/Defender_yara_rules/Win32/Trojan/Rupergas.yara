rule Trojan_Win32_Rupergas_A_2147650675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rupergas.A"
        threat_id = "2147650675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rupergas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "opPhmwBKAhmqITGKiIGQJOCGTDph" wide //weight: 4
        $x_2_2 = "62484245545F0B026D5C5D47555" wide //weight: 2
        $x_2_3 = "757709090078727A037A7E79717" wide //weight: 2
        $x_2_4 = "625243584146515E561E72585C5C" wide //weight: 2
        $x_2_5 = "7E776566736A756D7D5D524256425E5F" wide //weight: 2
        $x_2_6 = "745F50535D57746570" wide //weight: 2
        $x_2_7 = "62544575667D6A746751584455" wide //weight: 2
        $x_2_8 = "5E574546534A556D7D5D524256425E" wide //weight: 2
        $x_2_9 = "46585F5C565F4C430B4B5D5C405C434" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

