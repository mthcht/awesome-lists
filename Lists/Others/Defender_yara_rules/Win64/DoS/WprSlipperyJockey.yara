rule DoS_Win64_WprSlipperyJockey_A_2147966855_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win64/WprSlipperyJockey.A!dha"
        threat_id = "2147966855"
        type = "DoS"
        platform = "Win64: Windows 64-bit platform"
        family = "WprSlipperyJockey"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 89 74 24 38 48 8d 44 24 40 48 89 44 24 30 45 33 c9 44 89 74 24 28 45 33 c0 ba 00 c1 07 00 4c 89 74 24 20 48 8b ce ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {5b 00 53 00 48 00 41 00 44 00 4f 00 57 00 5d 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 72 00 65 00 73 00 69 00 7a 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 ?? ?? 73 00 74 00 6f 00 72 00 61 00 67 00 65 00 20 00 6f 00 6e 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 00 53 00 48 00 41 00 44 00 4f 00 57 00 5d 00 20 00 52 00 65 00 73 00 69 00 7a 00 65 00 64 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 ?? ?? 73 00 74 00 6f 00 72 00 61 00 67 00 65 00 20 00 6f 00 6e 00 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5b 00 50 00 52 00 49 00 56 00 5d 00 20 00 47 00 6f 00 74 00 20 00 53 00 45 00 5f 00 42 00 41 00 43 00 4b 00 55 00 50 00 5f 00 4e 00 41 00 4d 00 45 00 ?? ?? 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 2e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5b 00 57 00 41 00 52 00 4e 00 5d 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 67 00 65 00 74 00 20 00 53 00 45 00 5f 00 42 00 41 00 43 00 4b 00 55 00 50 00 5f 00 4e 00 41 00 4d 00 45 00 ?? ?? 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

