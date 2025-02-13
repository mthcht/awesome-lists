rule TrojanDownloader_AutoIt_Amigab_A_2147716344_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AutoIt/Amigab.A!bit"
        threat_id = "2147716344"
        type = "TrojanDownloader"
        platform = "AutoIt: AutoIT scripts"
        family = "Amigab"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {23 00 41 00 75 00 74 00 6f 00 49 00 74 00 33 00 57 00 72 00 61 00 70 00 70 00 65 00 72 00 5f 00 49 00 63 00 6f 00 6e 00 3d 00 2e 00 2e 00 5c 00 2e 00 2e 00 5c 00 42 00 61 00 6e 00 6b 00 73 00 5c 00 42 00 6f 00 74 00 6f 00 65 00 73 00 20 00 2b 00 [0-128] 2e 00 69 00 63 00 6f 00}  //weight: 10, accuracy: Low
        $x_1_2 = {42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 49 00 4e 00 45 00 54 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 5f 00 42 00 41 00 53 00 45 00 36 00 34 00 44 00 45 00 43 00 4f 00 44 00 45 00 20 00 28 00 [0-153] 29 00 20 00 29 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 49 00 4e 00 45 00 54 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-153] 2e 00 7a 00 69 00 70 00 22 00 20 00 29 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-32] 20 00 26 00 20 00 [0-153] 2c 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 54 00 4f 00 42 00 49 00 4e 00 41 00 52 00 59 00 20 00 28 00 20 00 24 00 [0-32] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {53 00 48 00 45 00 4c 00 4c 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-32] 20 00 26 00 20 00 22 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 00 43 00 6f 00 70 00 79 00 48 00 65 00 72 00 65 00 20 00 28 00 20 00 24 00 [0-32] 20 00 2c 00 20 00 24 00 [0-32] 20 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

