rule Worm_Win32_Pobtiz_2147616687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pobtiz"
        threat_id = "2147616687"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pobtiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 33 45 d0 0f bf d0 52 ff 15 ?? ?? ?? ?? 8b d0 8d 4d c8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d4 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {66 33 45 d0 0f bf c0 50 e8 ?? ?? ?? ?? 8b d0 8d 4d c8 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b d0 8d 4d d4 e8}  //weight: 10, accuracy: Low
        $x_10_3 = {6b 70 ff fb 12 e7 0b ?? 00 04 00 23 44 ff 2a 31 74 ff 32 04 00 48 ff 44 ff 35 4c ff 00 0c 6b 70 ff f3 ff 00 c6 1c ?? ?? 00 07 f4 01 70 70 ff 1e ?? ?? 00 0b 6b 70 ff f4 01 a9 70 70 ff 00 0a 04 72 ff 64 6c}  //weight: 10, accuracy: Low
        $x_1_4 = {00 73 70 72 65 64 31 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 74 6f 62 65 73 68 6f 72 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 68 69 64 65 69 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {72 00 65 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 74 00 68 00 65 00 20 00 61 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 61 00 67 00 61 00 69 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = "\\Ares\\My Shared Folder\\share\\" wide //weight: 1
        $x_1_9 = {00 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

