rule Ransom_Win32_Rotocrypt_A_2147725973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rotocrypt.A"
        threat_id = "2147725973"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rotocrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 00 66 c7 45 ?? 6e 00 66 c7 45 ?? 6c 00 66 c7 45 ?? 2e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2a 00 66 c7 45 ?? 2e 00 66 c7 45 ?? 2a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {65 00 66 c7 45 ?? 78 00 66 c7 45 ?? 65 00 66 c7 45 ?? 2e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 66 c7 45 ?? 65 00 66 c7 45 ?? 6e 00 66 c7 45 ?? 6f 00 66 c7 45 ?? 5a 00 66 c7 45 ?? 3a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 45 f8 61 c6 45 f7 74 c6 45 f6 61 c6 45 f5 64 c6 45 f4 2e}  //weight: 1, accuracy: High
        $x_1_6 = {6e 00 66 c7 45 ?? 65 00 66 c7 45 ?? 70 00 66 c7 45 ?? 6f 00}  //weight: 1, accuracy: Low
        $x_4_7 = {57 ff 24 85 ?? ?? ?? ?? 81 7c 24 2c 60 02 00 00 75 10 81 be ?? ?? 00 00 be ba fe ca 0f 84 ?? ?? 00 00 e8 ?? ?? ff ff}  //weight: 4, accuracy: Low
        $x_4_8 = {6a 40 68 00 10 00 00 68 40 9c 00 00 57 ff 96 ?? ?? 00 00 89 46 1c e8 ?? ?? ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

