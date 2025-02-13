rule TrojanSpy_Win32_Streespyer_A_2147628878_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Streespyer.A"
        threat_id = "2147628878"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Streespyer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "TFM_S3C_KL_MENS" wide //weight: 10
        $x_10_2 = "Ts3c_Reg_Win" ascii //weight: 10
        $x_1_3 = "TFM_S3C_SK21_LOGIN" wide //weight: 1
        $x_1_4 = "TFM_S3C_K13_LOGIN" wide //weight: 1
        $x_1_5 = {45 78 65 63 75 74 65 5f 78 43 6c 6f 73 65 5f 4f 70 65 6e [0-10] 53 65 72 76 69 63 65 50 61 75 73 65 [0-10] 54 53 70 6f 6f 6c}  //weight: 1, accuracy: Low
        $x_1_6 = {5b 68 73 52 65 73 6f 6c 76 69 6e 67 5d [0-12] 5b 68 73 43 6f 6e 6e 65 63 74 69 6e 67 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Streespyer_D_2147628917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Streespyer.D"
        threat_id = "2147628917"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Streespyer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FWndProcPtr0040000000000001" wide //weight: 1
        $x_1_2 = {16 53 65 72 76 69 63 65 42 65 66 6f 72 65 55 6e 69 6e 73 74 61 6c 6c ?? ?? ?? ?? ?? ?? 18 4d 65 73 73 61 67 65 5f 54 65 63 6c 61 73 5f 64 65 5f 41 74 61 6c 68 6f 0a 54 52 70 63 4c 6f 6f 6b 75 70}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 10 0f b6 00 8b 55 0c 0f b6 44 02 ff 8b 55 10 0f b6 52 01 8b 4d 0c 0f b6 54 11 ff 03 c2 8b 55 10 0f b6 52 02 8b 4d 0c 0f b6 54 11 ff 03 c2 89 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

