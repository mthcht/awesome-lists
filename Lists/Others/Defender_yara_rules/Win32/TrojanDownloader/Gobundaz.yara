rule TrojanDownloader_Win32_Gobundaz_A_2147688666_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gobundaz.A"
        threat_id = "2147688666"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gobundaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 4e 46 45 43 54 20 46 41 43 45 20 4e [0-3] 20 2d 20}  //weight: 10, accuracy: Low
        $x_4_2 = "\\syst.dat" ascii //weight: 4
        $x_4_3 = "insdb.php?table=" ascii //weight: 4
        $x_1_4 = {72 2c 2f 73 35 38 40 34 2d 32 39 73 ?? 71 36 32 32 3f 3c 3e 40 3b 73 2e 32 2d 32 3b 72 72 67 31}  //weight: 1, accuracy: Low
        $x_1_5 = "r2;38s-.29191.8-@/:s@=8<45@2></r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Gobundaz_B_2147693405_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gobundaz.B"
        threat_id = "2147693405"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gobundaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 4e 46 45 43 54 20 46 41 43 45 20 43 4c 49 20 [0-6] 20 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {49 4e 46 45 43 54 20 42 41 4e 4b 20 [0-6] 20 2d}  //weight: 1, accuracy: Low
        $x_1_3 = {49 4e 46 45 43 54 20 4d 41 4c 49 47 4e 4f 20 [0-6] 20 2d}  //weight: 1, accuracy: Low
        $x_1_4 = {49 4e 46 45 43 54 20 69 54 4d 50 20 [0-6] 20 2d}  //weight: 1, accuracy: Low
        $x_2_5 = {5c 68 6f 73 74 2e 64 61 74 00}  //weight: 2, accuracy: High
        $x_2_6 = {5c 64 72 76 2e 64 61 74 00}  //weight: 2, accuracy: High
        $x_5_7 = "insdb.php?table=" ascii //weight: 5
        $x_5_8 = "r2;38s-.29191.8-@/:s@=8<45@2></r" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

