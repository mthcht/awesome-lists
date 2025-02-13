rule TrojanSpy_Win32_Wagiclas_A_2147667656_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wagiclas.A"
        threat_id = "2147667656"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wagiclas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "410"
        strings_accuracy = "Low"
    strings:
        $x_300_1 = {c1 e2 06 03 c2 33 d2 8a 53 02 0f b6 92 ?? ?? ?? 00 c1 e2 0c 03 c2 33 d2 8a 53 03 0f b6 92 ?? ?? ?? 00 c1 e2 12}  //weight: 300, accuracy: Low
        $x_50_2 = "GlhklasKfz8rx2hTeAZ9MyJkpm" ascii //weight: 50
        $x_25_3 = "h8uNLwGwqc3rU2ohN" ascii //weight: 25
        $x_25_4 = "B4lbIgavlmScKHfC" ascii //weight: 25
        $x_30_5 = "GlhklasKfz8rx2hTeAZ9MyJkpmx5cVdxfJ6pvFPw7p9BPC" ascii //weight: 30
        $x_30_6 = "L1QSPiqWP4766YqMpmvZFsaRIUM" ascii //weight: 30
        $x_20_7 = "dx5EFOWoCeaOOZV72B" ascii //weight: 20
        $x_20_8 = "SA1lHPsn9oUz+ZKe" ascii //weight: 20
        $x_20_9 = "SowAA9ZwDz5jqBO" ascii //weight: 20
        $x_20_10 = "SUBPKTFJaoC" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_300_*) and 2 of ($x_25_*) and 3 of ($x_20_*))) or
            ((1 of ($x_300_*) and 1 of ($x_30_*) and 4 of ($x_20_*))) or
            ((1 of ($x_300_*) and 1 of ($x_30_*) and 1 of ($x_25_*) and 3 of ($x_20_*))) or
            ((1 of ($x_300_*) and 1 of ($x_30_*) and 2 of ($x_25_*) and 2 of ($x_20_*))) or
            ((1 of ($x_300_*) and 2 of ($x_30_*) and 3 of ($x_20_*))) or
            ((1 of ($x_300_*) and 2 of ($x_30_*) and 1 of ($x_25_*) and 2 of ($x_20_*))) or
            ((1 of ($x_300_*) and 2 of ($x_30_*) and 2 of ($x_25_*))) or
            ((1 of ($x_300_*) and 1 of ($x_50_*) and 3 of ($x_20_*))) or
            ((1 of ($x_300_*) and 1 of ($x_50_*) and 1 of ($x_25_*) and 2 of ($x_20_*))) or
            ((1 of ($x_300_*) and 1 of ($x_50_*) and 2 of ($x_25_*) and 1 of ($x_20_*))) or
            ((1 of ($x_300_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_300_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_25_*) and 1 of ($x_20_*))) or
            ((1 of ($x_300_*) and 1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_25_*))) or
            ((1 of ($x_300_*) and 1 of ($x_50_*) and 2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Wagiclas_B_2147678680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wagiclas.B"
        threat_id = "2147678680"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wagiclas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 fb 8b 55 00 8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f ?? ?? ?? ?? 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43}  //weight: 5, accuracy: Low
        $x_5_2 = {c1 e2 06 03 c2 33 d2 8a 53 02 0f b6 92 ?? ?? ?? 00 c1 e2 0c 03 c2 33 d2 8a 53 03 0f b6 92 ?? ?? ?? 00 c1 e2 12}  //weight: 5, accuracy: Low
        $x_1_3 = "GlhklasKfz" ascii //weight: 1
        $x_1_4 = "dx5EFOWoCeaOOZV72B" ascii //weight: 1
        $x_1_5 = "SA1laHpfU2OO" ascii //weight: 1
        $x_1_6 = "EkMwqXGYV8N" ascii //weight: 1
        $x_1_7 = "PpqC24xIeEGdWD" ascii //weight: 1
        $x_1_8 = "FFGjif31" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

