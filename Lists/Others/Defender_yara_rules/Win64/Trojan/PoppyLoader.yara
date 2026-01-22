rule Trojan_Win64_PoppyLoader_F_2147961634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoppyLoader.F!dha"
        threat_id = "2147961634"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoppyLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 44 6c 6c 4c 6f 61 64 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 65 78 65 00 41 45 53 5f 6f 70 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 64 6c 6c 00 41 45 53 5f 6f 70 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "LoadMimi" ascii //weight: 1
        $x_1_5 = {00 50 75 62 6c 69 63 4c 6f 61 64 65 72 36 34 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 4e 50 4d 4c 6f 61 64 65 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 44 6c 6c 4c 6f 61 64 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = "X#9gTim2@Vq4Lz&7" ascii //weight: 1
        $x_1_9 = "MemloadFunc" ascii //weight: 1
        $x_1_10 = {0c ab 00 00 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {4c 8b 1f 41 8b ?? 28 85 ?? 74 ?? ?? 03 ?? 74 ?? ?? 8b ?? ba 01 00 00 00 ?? 8b ?? ff ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_12 = {48 8b 07 8b ?? 28 85 ?? 74 ?? 8b ?? ?? 03 ?? 74 ?? ?? 8b ?? ba 01 00 00 00 ?? 8b ?? ff ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_13 = {48 8b 07 8b ?? 28 85 ?? 74 ?? 8b ?? ?? 03 ?? 74 ?? ?? 33 ?? ?? 8b ?? ?? 8d ?? 01 ff ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_14 = {4c 8b 1f 41 8b ?? 28 85 ?? 74 ?? ?? 03 ?? 74 ?? ?? 33 ?? ?? 8b ?? ?? 8d ?? 01 ff ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

