rule Virus_Win32_Demig_B_2147600078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Demig.B"
        threat_id = "2147600078"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Demig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3b 50 45 00 00 0f 84 ?? ?? 00 00 66 81 3b 4e 45 0f 85 ?? ?? 00 00 8b bd ?? ?? ?? ?? 8b f7 80 3f 5c}  //weight: 1, accuracy: Low
        $x_1_2 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 0d 0a 4f 70 65 6e 20 22 43 3a 5c 64 65 6d 69 75 72 67 2e 65 78 65 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 31 0d 0a 62 0d 0a 63 0d 0a 64 0d 0a 65 0d 0a 66 0d 0a 67 0d 0a 43 6c 6f 73 65 20 23 31 0d 0a 74 3d 53 68 65 6c 6c 28 22 43 3a 5c 64 65 6d 69 75 72 67 2e 65 78 65 22 2c 76 62}  //weight: 1, accuracy: High
        $x_1_3 = {43 3a 5c 44 45 4d 49 55 52 47 2e 45 58 45 00 00 00 80 00 00 00 ff ff ff ff ff ff ff ff 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 6f 76 65 72 6c 61 79 3d 25 30 0d 0a 69 66 20 6e 6f 74 20 65 78 69 73 74 20 25 6f 76 65 72 6c 61 79 25 20 73 65 74 20 6f 76 65 72 6c 61 79 3d 25 30 2e 42 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

