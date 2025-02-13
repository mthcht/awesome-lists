rule Trojan_Win32_Cecapix_A_2147625346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cecapix.A"
        threat_id = "2147625346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cecapix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 34 53 ff 93 ?? ?? ?? ?? c1 e0 06 8d 84 18 ?? ?? ?? ?? 50 ff b3 ?? ?? ?? ?? ff 93}  //weight: 2, accuracy: Low
        $x_2_2 = {81 7d e4 9a 02 00 00 6a 05 50 50 8d 8b ?? ?? ?? ?? 74 06}  //weight: 2, accuracy: Low
        $x_1_3 = {75 a6 eb 10 6a 00 6a 00 68 f5 00 00 00 57 ff 96 ?? ?? ?? ?? 5e}  //weight: 1, accuracy: Low
        $x_1_4 = {48 48 46 83 fe 08 7c c0 6a 22 68 ?? ?? ?? ?? 6a 02}  //weight: 1, accuracy: Low
        $x_1_5 = "taskurl" wide //weight: 1
        $x_1_6 = "capurl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

