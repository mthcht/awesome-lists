rule Trojan_Win64_Kazuar_C_2147902705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kazuar.C!dha"
        threat_id = "2147902705"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kazuar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 31 c0 44 8b 54 24 38 49 89 cb 41 8d 48 01 48 89 d7 48 01 c9 89 c9 f3 aa 31 c0 41 8a 0c 03 45 0f af d1 44 03 54 24 30 44 31 d1 0f b6 c9 66 89 0c 42 48 ff c0 41 39 c0 77 e1 5f c3}  //weight: 10, accuracy: High
        $x_10_2 = {57 31 c0 44 8b 54 24 38 49 89 cb 48 89 d7 41 8d 48 01 f3 aa 31 c0 41 8a 0c 03 45 0f af d1 44 03 54 24 30 44 31 d1 88 0c 02 48 ff c0 41 39 c0 77 e5 5f c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

