rule Backdoor_Win64_LamanchaGoat_A_2147973385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/LamanchaGoat.A!dha"
        threat_id = "2147973385"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "LamanchaGoat"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 68 18 c7 44 24 20 01 00 00 00 ba ?? ?? 00 00 66 33 17 48 8b c3 48 8d 4b 18 48 83 7b 18 07 76 ?? 48 8b 03 66 89 10 b8 ?? ?? 00 00 66 33 47 02 48 8b d3 48 83 7b 18 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

