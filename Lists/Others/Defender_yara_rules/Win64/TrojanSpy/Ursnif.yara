rule TrojanSpy_Win64_Ursnif_B_2147648285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Ursnif.B"
        threat_id = "2147648285"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?version=%u&user=%x%x%x%x&server=%u&id=%u" ascii //weight: 1
        $x_1_2 = {b9 ff 03 1f 00 ff 15 ?? ?? ?? ?? 48 85 c0 48 8b f8 74 18 45 33 c0 48 8b d0 48 8b ce ff 15 ?? ?? ?? ?? 48 8b cf ff 15 ?? ?? ?? ?? 48 8d 54 24 ?? 48 8b cb e8 ?? ?? ?? ?? 85 c0 75 ?? 48 8b cb ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win64_Ursnif_A_2147651085_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Ursnif.A"
        threat_id = "2147651085"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {81 39 48 54 54 50 74 0c 81 39 50 4f 53 54 0f 85}  //weight: 3, accuracy: High
        $x_3_2 = {81 3a 47 45 54 20 74 14 81 3a 50 55 54 20 74 0c 81 3a 50 4f 53 54 0f 85}  //weight: 3, accuracy: High
        $x_3_3 = {c6 00 36 c6 40 01 34 48 83 c0 02 48 8d 15 ?? ?? ?? ?? 48 8b ?? c6 00 00}  //weight: 3, accuracy: Low
        $x_3_4 = {48 8b 4f 08 ff 15 ?? ?? ?? ?? b9 64 00 00 00 ff 15 ?? ?? ?? ?? 48 8b 4f 08 ff 15 ?? ?? ?? ?? 48 8b 4f 08 48 8d 54 24 30 ff 15 ?? ?? ?? ?? 83 c3 9c 74 0a 48 39 b4 24 28 01 00 00 75 c3}  //weight: 3, accuracy: Low
        $x_3_5 = {44 0f be 09 41 03 d3 41 ba 08 00 00 00 48 ff c1 41 8b c1 41 33 c0 41 d1 e8 a8 01 74 07}  //weight: 3, accuracy: High
        $x_3_6 = {41 8b 02 ff c1 41 33 c3 45 8b 1a 41 33 c0 d3 c8 41 89 02 49 83 c2 04 83 c2 ff 75 d9}  //weight: 3, accuracy: High
        $x_3_7 = {b8 1f 85 eb 51 41 f7 eb c1 fa 03 8b c2 c1 e8 1f 03 d0 6b d2 19 44 2b da 41 80 c3 61 44 88 5d 00 48 ff c5 48 ff cf 75 cd}  //weight: 3, accuracy: High
        $x_3_8 = {83 c1 01 41 d3 c0 45 33 d0 45 33 d3 44 89 10 48 83 c0 04 83 c2 ff 75 d0}  //weight: 3, accuracy: High
        $x_3_9 = {02 c2 41 80 f9 09 41 88 00 41 8b c3 0f 4f c3 49 83 c0 02 48 83 c1 01 41 02 c1 49 83 ea 01 41 88 40 ff 75 c6}  //weight: 3, accuracy: High
        $x_1_10 = "user_id=%.4u&version_id=%lu&socks=%lu&build=%lu&crc=%.8x" ascii //weight: 1
        $x_1_11 = "version=%u&user=%x%x%x%x&server=%u&id=%u" ascii //weight: 1
        $x_1_12 = "?crc=%x&version=%u&user=%x%x%x%x&id=%u&server=%u" ascii //weight: 1
        $x_1_13 = {4e 45 57 47 52 41 42 00}  //weight: 1, accuracy: High
        $x_1_14 = {44 4c 5f 45 58 45 00 00 44 4c 5f 45 58 45 5f 53 54 00}  //weight: 1, accuracy: High
        $x_1_15 = {55 52 4c 3a 20 25 73 0d 0a 75 73 65 72 3d 25 73 0d 0a 70 61 73 73 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_16 = {2f 55 50 44 00 2f 53 44 00 2f 73 64 20 20 25 6c 75 00}  //weight: 1, accuracy: High
        $x_1_17 = "version=%u&user=%s&server=%u&id=%u&type=%u&name=%s" ascii //weight: 1
        $x_1_18 = "makecab.exe /F \"%s\"" ascii //weight: 1
        $x_1_19 = "version=%s&group=%s&client=%s" ascii //weight: 1
        $x_1_20 = "/tasks?version=%s" wide //weight: 1
        $x_1_21 = "/data?version=%s" wide //weight: 1
        $x_1_22 = "data.php?version=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" ascii //weight: 1
        $x_1_23 = {2f 75 70 64 20 25 6c 75 00}  //weight: 1, accuracy: High
        $x_1_24 = "/U /C \"type %s1 > %s & del %s1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win64_Ursnif_BB_2147686159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Ursnif.BB"
        threat_id = "2147686159"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 15 b8 72 00 00 48 8d 4c 24 4c ff 15 ed 6d 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 15 c2 72 00 00 48 8d 4c 24 4c ff 15 d7 6d 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 8d 15 c4 72 00 00 48 8d 4c 24 4c ff 15 c1 6d 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {48 8d 15 af 7b 00 00 ff 15 29 70 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 8b cd 4c 8b c7 49 8b d6 48 8b ce 48 89 44 24 20 e8 9c fb ff ff}  //weight: 1, accuracy: High
        $x_1_6 = "reg.exe query \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" /s >> %s" wide //weight: 1
        $x_1_7 = "cmd /C \"systeminfo.exe > %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

