rule Trojan_Win64_Scavenger_A_2147962354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Scavenger.A!AMTB"
        threat_id = "2147962354"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Scavenger"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 05 41 58 11 00 48 33 c4 48 89 44 24 58 48 8d 84 24 88 00 00 00 48 89 44 24 50 48 8b 44 24 50 48 89 44 24 40 48 8b 84 24 80 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 05 d9 75 15 00 48 33 c4 48 89 85 68 01 00 00 48 c7 45 08 00 00 00 00 c7 85 60 01 00 00 00 00 00 00 48 8b 84 24 a0 01 00 00 48 89 45 18 83 3d 3a a9 15 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

