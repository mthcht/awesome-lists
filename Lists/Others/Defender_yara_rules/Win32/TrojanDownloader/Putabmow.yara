rule TrojanDownloader_Win32_Putabmow_A_2147697380_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Putabmow.A"
        threat_id = "2147697380"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Putabmow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5d 14 8a cc f6 d3 f6 d1 22 4d 14 8a c3 22 c4 0a c8 88 0c 17 8b 7e 14 83 ff 10 72 04 8b 06 eb 02 8b c6 8a 0c 10 8a d1 22 d9 f6 d2 22 55 14 0a d3 88 55 14 8b 55 f0 42 89 55 f0 3b 56 10 72}  //weight: 1, accuracy: High
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 57 6f 6d 62 61 74 55 70 64 61 74 65 72 5c 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 63 00 00 38 61 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {8a 14 78 8b 45 0c 8a ca 8a d8 f6 d1 22 c8 f6 d3 8a c3 22 c2 0a c8 0f b6 c1 66 89 04 7e}  //weight: 1, accuracy: High
        $x_1_5 = {68 a0 00 00 00 6a 20 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 c6 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Putabmow_B_2147697381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Putabmow.B"
        threat_id = "2147697381"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Putabmow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 57 00 6f 00 6d 00 62 00 61 00 74 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 5c 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "/S /VERYSILENT /SUPPRESSMSGBOXES /update" wide //weight: 2
        $x_1_3 = {6c 00 61 00 73 00 74 00 5f 00 63 00 68 00 65 00 63 00 6b 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 2f 00 75 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_2_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 5c 00 00 00}  //weight: 2, accuracy: High
        $x_2_6 = "/S /STOPLOOKING AT MY CODE SERIOUSLY!!!!" wide //weight: 2
        $x_2_7 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 49 00 6e 00 6e 00 6f 00 63 00 65 00 6e 00 74 00 4b 00 65 00 79 00 5c 00 00 00}  //weight: 2, accuracy: High
        $x_1_8 = {2f 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 2f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

