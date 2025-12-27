rule Trojan_Win64_MunchyHill_A_2147945780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MunchyHill.A!dha"
        threat_id = "2147945780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MunchyHill"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 3a 20 54 68 65 20 66 69 72 73 74 20 6c 65 76 65 6c 20 43 41 4c 4c 2f 4a 4d 50 20 69 6e 73 74 72 75 63 74 69 6f 6e 20 77 61 73 20 6e 6f 74 20 66 6f 75 6e 64 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 6c 65 61 72 20 4f 62 6a 65 63 74 20 43 61 6c 6c 62 61 63 6b 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 6c 65 61 72 20 52 65 67 69 73 74 72 79 20 43 61 6c 6c 62 61 63 6b 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {46 4c 54 4d 47 52 2e 53 59 53 00}  //weight: 1, accuracy: High
        $x_1_5 = "SentinelAgent.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

