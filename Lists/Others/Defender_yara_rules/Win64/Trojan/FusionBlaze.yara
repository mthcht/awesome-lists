rule Trojan_Win64_FusionBlaze_A_2147725397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FusionBlaze.A!dha"
        threat_id = "2147725397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FusionBlaze"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 10 57 48 83 ec 70 bf 01 00 00 00 8b d7 44 8d 47 05 8d 4f 01 ff 15 ?? ?? ?? ?? 89 7c 24 50 33 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b d8 48 89 7c 24 40 48 89 7c 24 38 48 8d 84 24 80 00 00 00 44 8d 4f 0c 4c 8d 44 24 50 48 89 44 24 30 48 8d 44}  //weight: 1, accuracy: High
        $x_1_3 = {24 60 44 89 4c 24 28 ba 04 00 00 98 48 8b cb c7 44 24 54 00 f4 01 00 48 89 44 24 20 c7 44 24 58 e8 03 00 00 89 bc}  //weight: 1, accuracy: High
        $x_1_4 = {24 80 00 00 00 ff 15 ?? ?? ?? ?? 83 f8 ff 48 0f 44 df 48 8b c3 48 8b 9c 24 88 00 00 00 48 83 c4 70 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_FusionBlaze_A_2147725397_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FusionBlaze.A!dha"
        threat_id = "2147725397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FusionBlaze"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 69 6e 6a 65 63 74 50 45 5d 20 73 76 63 4e 61 6d 65 3d 25 73 20 6d 6f 64 75 6c 65 50 61 74 68 3d 25 73 7c 20 70 69 64 3d 25 64 20 74 69 64 3d 25 64 20 68 4d 6f 64 75 6c 65 3d 30 78 25 70 20 65 6e 74 72 79 3d 30 78 25 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 43 6f 70 79 4d 6f 64 75 6c 65 5d 20 73 76 63 4e 61 6d 65 3d 25 73 20 6d 6f 64 75 6c 65 50 61 74 68 3d 25 73 7c 20 70 69 64 3d 25 64 20 74 69 64 3d 25 64 20 68 4d 6f 64 75 6c 65 3d 30 78 25 70 20 65 6e 74 72 79 3d 30 78 25 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 65 43 6f 6e 66 69 67 20 73 75 63 63 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FusionBlaze_A_2147725397_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FusionBlaze.A!dha"
        threat_id = "2147725397"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FusionBlaze"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 69 6e 6a 65 63 74 50 45 5d 20 73 76 63 4e 61 6d 65 3d 25 73 20 6d 6f 64 75 6c 65 50 61 74 68 3d 25 73 7c 20 70 69 64 3d 25 64 20 74 69 64 3d 25 64 20 68 4d 6f 64 75 6c 65 3d 30 78 25 70 20 65 6e 74 72 79 3d 30 78 25 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 43 6f 70 79 4d 6f 64 75 6c 65 5d 20 73 76 63 4e 61 6d 65 3d 25 73 20 6d 6f 64 75 6c 65 50 61 74 68 3d 25 73 7c 20 70 69 64 3d 25 64 20 74 69 64 3d 25 64 20 68 4d 6f 64 75 6c 65 3d 30 78 25 70 20 65 6e 74 72 79 3d 30 78 25 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 65 43 6f 6e 66 69 67 20 46 61 69 6c 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = "%[^:]:%[^:]:%[^:]:%s" ascii //weight: 1
        $x_1_5 = {52 65 43 6f 6e 66 69 67 20 73 75 63 63 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

