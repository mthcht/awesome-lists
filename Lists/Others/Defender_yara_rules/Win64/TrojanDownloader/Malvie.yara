rule TrojanDownloader_Win64_Malvie_A_2147852891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Malvie.A"
        threat_id = "2147852891"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Malvie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 33 00 c7 ?? ?? ?? 2e 00 6f 00 c7 ?? ?? ?? 72 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 00 45 00 c7 ?? ?? 54 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {73 00 3a 00 [0-10] 2f 00 2f 00 e8 ?? ?? 00 00 81 3b 68 74 74 70}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 80 fc ec 04 e8 20 00 0d 0a 41 ?? 06 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

