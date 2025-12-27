rule TrojanDownloader_Win64_Stealc_H_2147958392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Stealc.H!AMTB"
        threat_id = "2147958392"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 09 c7 44 24 28 00 04 00 00 48 8d 84 24 80 02 00 00 48 89 44 24 20 41 b9 ff ff ff ff 4c 8b c1 33 d2 b9 e9 fd 00 00 ff 15 cb f9 00 00 4c 89 74 24 28 44 89 74 24 20 41 b9 04 01 00 00 4c 8d 44 24 70 48 8d 94 24 80 02 00 00 33 c9 e8 af 07 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {0f 28 05 1c f8 00 00 48 8d 4c 24 20 48 89 44 24 20 48 c7 44 24 30 45 00 00 00 48 c7 44 24 38 4f 00 00 00 0f 11 00 0f 28 0d 06 f8 00 00 0f 11 48 10 0f 28 05 0b f8 00 00 0f 11 40 20 0f 28 0d 10 f8 00 00 0f 11 48 30 f2 0f 10 05 11 f8 00 00 f2 0f 11 40 3d c6 40 45 00 e8 f6 f9 ff ff}  //weight: 2, accuracy: High
        $x_3_3 = {68 74 74 70 3a 2f 2f 31 39 36 2e 32 35 31 2e 31 30 37 2e 39 34 3a 35 35 35 33 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5f 62 75 69 6c 64 2e 62 69 6e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_Stealc_I_2147958393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Stealc.I!AMTB"
        threat_id = "2147958393"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Stealc"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {4c 8b 05 67 7a 01 00 48 8d 15 a0 df 00 00 48 8d 8c 24 90 00 00 00 ff 15 ea dc 00 00 33 d2 c7 44 24 20 70 00 00 00 48 8d 4c 24 24 44 8d 42 6c e8 ca c3 00 00 48 8d 05 9b df 00 00 c7 44 24 50 00 00 00 00 48 89 44 24 38 48 8d 4c 24 20 48 8d 84 24 90 00 00 00 c7 44 24 24 40 00 00 00 48 89 44 24 40 ff 15 8e dc 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {4c 8b 05 97 79 01 00 48 8d 15 b0 de 00 00 48 8d 8c 24 90 00 00 00 ff 15 1a dc 00 00 33 d2 c7 44 24 20 70 00 00 00 48 8d 4c 24 24 44 8d 42 6c e8 fa c2 00 00 48 8d 05 93 de 00 00 c7 44 24 50 00 00 00 00 48 89 44 24 38 48 8d 4c 24 20 48 8d 84 24 90 00 00 00 48 89 44 24 40 ff 15 c6 db 00 00}  //weight: 3, accuracy: High
        $x_3_3 = "https://arskillshub.online/wp-content/uploads/backup_a459b8a0e8cb/update.exe" ascii //weight: 3
        $x_1_4 = "/c bitsadmin /transfer" ascii //weight: 1
        $x_1_5 = "certutil.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

