rule Trojan_Win64_StormWiper_A_2147963987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StormWiper.A!dha"
        threat_id = "2147963987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StormWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\??\\Z:\\" wide //weight: 1
        $x_1_2 = "Working on updates. Don't turn off your PC .." wide //weight: 1
        $x_1_3 = {b9 04 00 00 00 f3 aa 48 [0-48] c7 44 24 ?? 00 00 01 00 48 81 7c 24 ?? 00 00 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

