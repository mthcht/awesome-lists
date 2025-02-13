rule TrojanDownloader_Win32_Obcatde_A_2147697620_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Obcatde.A"
        threat_id = "2147697620"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Obcatde"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 8b d8 8b 43 60 8a 40 6c 88 43 70 84 c0 74 4b 8b 43 60 80 78 78 00 74 25 66 83 bb 82 00 00 00 00 74 47 8b 50 70 52 8b 50 68 52 8b 48 4c 8b d3 8b 83 84 00 00 00 ff 93 80 00 00 00 eb 2c}  //weight: 1, accuracy: High
        $x_1_2 = {80 7f 78 00 74 17 8b 87 8c 00 00 00 99 3b 57 74 75 03 3b 47 70 0f 94 c0 88 47 6c eb 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

