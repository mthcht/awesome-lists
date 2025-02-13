rule TrojanDownloader_WinNT_Nupylos_A_2147623093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:WinNT/Nupylos.A"
        threat_id = "2147623093"
        type = "TrojanDownloader"
        platform = "WinNT: WinNT"
        family = "Nupylos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\??\\%ws\\System32\\DRIVERS\\nup.sys" wide //weight: 1
        $x_1_2 = "\\Device\\MyDRVS" wide //weight: 1
        $x_1_3 = "\\DosDevices\\MyDRVS" wide //weight: 1
        $x_1_4 = {25 73 3f 69 64 3d 25 77 73 26 64 6f 77 6e 6c 6f 61 64 3d 25 30 32 2e 38 58 20 48 54 54 50 2f 31 2e 30 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 3f 69 64 3d 25 77 73 20 48 54 54 50 2f 31 2e 30 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a}  //weight: 1, accuracy: High
        $x_1_6 = "/spm/index.php" ascii //weight: 1
        $x_1_7 = "myrx8.net" ascii //weight: 1
        $x_1_8 = "%ws.%02.8X.dll" ascii //weight: 1
        $x_2_9 = {75 f5 35 26 80 ac c8 74 0a 41 3b 4a 18 75 e1 33 c0 eb 1b}  //weight: 2, accuracy: High
        $x_2_10 = {c1 e0 02 8b 52 1c 03 d3 8b 04 02 03 c3 8b 5d 08 ff 33 ff d0 b8 de c0 ad de}  //weight: 2, accuracy: High
        $x_2_11 = {80 7f 09 32 0f 85 ?? 00 00 00 80 7f 0a 30 0f 85 ?? 00 00 00 80 7f 0b 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

