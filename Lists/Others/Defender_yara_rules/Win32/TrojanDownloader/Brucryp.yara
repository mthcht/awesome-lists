rule TrojanDownloader_Win32_Brucryp_A_2147686843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brucryp.A"
        threat_id = "2147686843"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brucryp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 65 00 72 00 74 00 5f 00 76 00 25 00 64 00 5f 00 25 00 64 00 2e 00 74 00 70 00 6c 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = {53 74 61 72 74 69 6e 67 20 63 72 79 70 74 6f 20 73 65 72 76 69 63 65 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 49 36 34 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 65 75 73 65 72 65 62 6f 6f 74 5f 25 64 5f 25 64 5f 25 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 73 65 72 72 6f 72 5f 25 64 5f 25 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 72 65 61 74 65 70 72 6f 63 61 5f 25 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 6c 6f 62 30 31 [0-2] 00 [0-16] 42 6c 6f 62 30 31 [0-2] 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 00 72 00 79 00 70 00 74 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {41 00 67 00 65 00 6e 00 74 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {2e 00 69 00 6e 00 73 00 74 00 73 00 79 00 6e 00 63 00 2e 00 65 00 75 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Brucryp_B_2147705473_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brucryp.B"
        threat_id = "2147705473"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brucryp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 65 00 72 00 74 00 5f 00 76 00 25 00 64 00 5f 00 25 00 64 00 2e 00 74 00 70 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {67 64 6d 76 65 64 00 00 2e 00 74 00 70 00 6c 00 00 00 64 00 30 00 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {65 00 76 00 65 00 6e 00 74 00 74 00 6f 00 73 00 79 00 6e 00 63 00 74 00 72 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Brucryp_C_2147706026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brucryp.C"
        threat_id = "2147706026"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brucryp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 65 00 72 00 74 00 5f 00 76 00 25 00 64 00 5f 00 25 00 64 00 2e 00 74 00 70 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 76 00 65 00 6e 00 74 00 74 00 6f 00 73 00 79 00 6e 00 63 00 74 00 72 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 00 70 00 63 00 68 00 6f 00 6f 00 6b 00 73 00 79 00 6e 00 63 00 [0-208] 25 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 25 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 5c 00 52 00 53 00 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Brucryp_D_2147706671_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brucryp.D"
        threat_id = "2147706671"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brucryp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%APPDATA%\\Microsoft\\SystemResources" wide //weight: 1
        $x_1_2 = {57 00 69 00 6e 00 52 00 65 00 73 00 53 00 79 00 6e 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 00 62 00 6e 00 73 00 73 00 79 00 6e 00 63 00 2e 00 75 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 72 00 79 00 70 00 74 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 2e 00 74 00 70 00 6c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Brucryp_D_2147706671_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brucryp.D"
        threat_id = "2147706671"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brucryp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 72 00 79 00 70 00 74 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 00 62 00 6e 00 73 00 73 00 79 00 6e 00 63 00 2e 00 75 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {69 00 70 00 63 00 73 00 79 00 6e 00 63 00 74 00 72 00 74 00 68 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {69 00 70 00 63 00 69 00 6e 00 70 00 72 00 6f 00 63 00 73 00 79 00 6e 00 63 00 00 00}  //weight: 2, accuracy: High
        $x_1_5 = {57 00 69 00 6e 00 52 00 65 00 73 00 53 00 79 00 6e 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {75 79 6c 6b 75 74 2e 74 70 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {64 73 66 73 64 66 2e 74 70 6c 00}  //weight: 1, accuracy: High
        $x_1_8 = "%APPDATA%\\Microsoft\\SystemResources" wide //weight: 1
        $x_1_9 = {63 00 65 00 72 00 74 00 5f 00 76 00 25 00 64 00 5f 00 25 00 64 00 2e 00 74 00 70 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {68 72 74 75 6b 6a 79 72 75 2e 74 70 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Brucryp_G_2147712138_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Brucryp.G"
        threat_id = "2147712138"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Brucryp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d1 c1 ea 1d 8b f9 c1 ef 1e 83 e2 01 83 e7 01 8d 14 57 8b f9 c1 ef 1f 8d 14 57 8b 14 95 ?? ?? 40 00 f7 c1 00 00 00 04 74}  //weight: 1, accuracy: Low
        $x_1_2 = "correcamins.net/fotos/bin.dat" wide //weight: 1
        $x_1_3 = "www.rbphoto.com.br/twg/bin.dat" wide //weight: 1
        $x_1_4 = "frauricambi.com/frau/bin.dat" wide //weight: 1
        $x_1_5 = "makingart.fr/images/bin.dat" wide //weight: 1
        $x_1_6 = ".halldeoccidente.com/eleccion2015/zatul.php" wide //weight: 1
        $x_1_7 = "gteng.it/zerif.php" wide //weight: 1
        $x_1_8 = "abavides.es/musica/rocu.php" wide //weight: 1
        $x_1_9 = "piensaenweb.net/contrato_autogestionable/tahyh.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

