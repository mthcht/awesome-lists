rule TrojanSpy_Win64_Lurk_A_2147695244_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Lurk.A"
        threat_id = "2147695244"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Lurk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 4f 48 83 64 24 30 00 48 8b 9c 24 70 01 00 00 48 83 64 24 28 00 83 64 24 20 00 4c 8d 4c 24 48 4c 8d 84 24 88 01 00 00 48 8d 54 24 50 48 8b cb e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b f2 75 0e 48 85 c9 75 09 85 db 74 20 83 c8 ff eb 79 85 db 74 17 48 85 c9 74 12 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {4d 8b c4 8b c3 f7 d8 48 8d 44 24 48 48 1b d2 48 89 44 24 38 c7 44 24 30 00 02 48 84 48 21 7c 24 28 48 21 7c 24 20 48 23 d1 49 8b cd 45 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 25 73 25 64 2e 63 6d 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "?hl=us&source=hp&q=%d&aq=f&aqi=&oq=" ascii //weight: 1
        $x_1_6 = {63 68 63 70 20 31 32 35 31 0d 0a 3a 6c 6f 6f 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

