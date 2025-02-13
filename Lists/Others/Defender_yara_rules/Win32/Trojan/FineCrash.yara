rule Trojan_Win32_FineCrash_A_2147902369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FineCrash.A!dha"
        threat_id = "2147902369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FineCrash"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba ab f2 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 c7 45 ?? 07 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 42 08 8b 49 10 48 83 c1 09 41 8b c0 4c 3b c1 72 e6 33 c0}  //weight: 1, accuracy: High
        $x_2_3 = {45 33 f6 44 89 74 24 ?? c7 45 ?? 43 00 3a 00 c7 45 ?? 5c 00 00 00 44 89 74 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

