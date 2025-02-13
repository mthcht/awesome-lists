rule TrojanDownloader_Win32_Votossa_A_2147694515_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Votossa.A"
        threat_id = "2147694515"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Votossa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6e 65 74 6f 70 65 6e 61 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6f 6e 6e 65 63 74 61 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {72 65 71 31 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 65 61 64 31 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {32 30 30 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 45 20 6e 6f 74 20 6f 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = {70 65 20 76 61 6c 69 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {69 6e 69 74 69 61 6c 69 7a 65 64 20 6f 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

