rule Trojan_Win64_SeaSickle_A_2147918782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SeaSickle.A!dha"
        threat_id = "2147918782"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SeaSickle"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8d 49 02 f7 e9 41 8b c9 c1 fa 03 8b c2 c1 e8 1f 03 d0 8d 04 92 c1 e0 02 2b c8 8d 41 02 42 0f b6 4c 13 01 48 98 42 2a 0c 18 b8 ?? ?? ?? ?? 41 88 4a 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

