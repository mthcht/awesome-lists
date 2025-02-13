rule Trojan_Win32_Stratork_A_2147652435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stratork.A"
        threat_id = "2147652435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stratork"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b7 5c 78 fe 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 eb 03}  //weight: 2, accuracy: High
        $x_1_2 = "Gogothelast" wide //weight: 1
        $x_1_3 = "stem is down. F.... Ev" wide //weight: 1
        $x_1_4 = "pedrocacarneiro@" wide //weight: 1
        $x_1_5 = "\\drivers\\texasrangers.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

