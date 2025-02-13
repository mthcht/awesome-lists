rule Trojan_Win64_SmallTiger_A_2147916853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SmallTiger.A!dha"
        threat_id = "2147916853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SmallTiger"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 3c 11 00 75 eb 48 8b 4c 24 ?? 33 d2 48 f7 f1 48 8b c2 48 8b 4c 24 ?? 0f b6 14 01 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? eb 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

