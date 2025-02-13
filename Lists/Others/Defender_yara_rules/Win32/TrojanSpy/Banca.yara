rule TrojanSpy_Win32_Banca_2147801394_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banca"
        threat_id = "2147801394"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 8d 44 24 18 6a 00 50 55 ff d3 8b 54 24 14 8d 4c 24 18 51 8d 84 24 60 23 00 00 52 50 55 ff 15 ?? ?? ?? ?? 8b 44 24 18 85 c0 74 44 8d bc 24 5c 23 00 00 83 c9 ff 33 c0 8d 54 24 1c f2 ae f7 d1 2b f9 8b f7 8b fa 8b d1 83 c9 ff f2 ae 8b ca 4f c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8d 7c 24 1c 83 c9 ff f2 ae f7 d1 49 81 f9 90 01 00 00 76 8f}  //weight: 10, accuracy: Low
        $x_10_2 = "InternetQueryDataAvailable" ascii //weight: 10
        $x_1_3 = "mycashbank.co.kr" ascii //weight: 1
        $x_1_4 = {68 3f 00 0f 00 50 50 ff d5 8b f0 85 f6 74 4d 8d 54 24 30 68 04 01 00 00 52 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 8d 44 24 40 6a 00 50 6a 01 6a 02 68 10 01 00 00 68 ff 01 0f 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 85 c0 74 03 50 ff d3 56 ff d3 68 3f 00 0f 00 6a 00 6a 00 ff d5 8b f8 85 ff 74 28 68 ff 01 0f 00 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 0e 6a 00 6a 00 56 ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {81 ec 80 06 00 00 56 57 b9 10 00 00 00 33 c0 8d 7c 24 08 f3 ab 88 44 24 38 8d 44 24 08 50 c6 44 24 0c 32 e8 ?? ?? ?? ?? b9 10 00 00 00 33 c0 8d 7c 24 08 8d 54 24 12 f3 ab bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 2b f9 88 44 24 38 8b c1 8b f7 8b fa c6 44 24 08 33 c1 e9 02 f3 a5 8b c8 8d 54 24 08 83 e1 03 52 f3 a4 8d 4c 24 4c 66 c7 44 24 14 58 02 89 4c 24 10 e8 ?? ?? ?? ?? 8a d0 b9 f9 00 00 00 33 c0 8d bc 24 a1 02 00 00 c6 84 24 a0 02 00 00 00 f3 ab 66 ab aa 5f 5e 84 d2 75 56 8b 44 24 45 8b 4c 24 44 8b 54 24 43 25 ff 00 00 00 81 e1 ff 00 00 00 50 8b 44 24 46 81 e2 ff 00 00 00 51 8b 4c 24 49 52 8b 54 24 4c 25 ff 00 00 00 81 e1 ff 00 00 00 50 81 e2 ff 00 00 00 51 52 8d 84 24 b0 02 00 00 68 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

