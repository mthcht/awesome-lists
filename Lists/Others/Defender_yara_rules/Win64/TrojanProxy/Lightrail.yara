rule TrojanProxy_Win64_Lightrail_A_2147918698_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win64/Lightrail.A"
        threat_id = "2147918698"
        type = "TrojanProxy"
        platform = "Win64: Windows 64-bit platform"
        family = "Lightrail"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 56 47 41 75 74 68 5f 41 64 64 41 6c 69 61 73 00 56 47 41 75 74 68 32 2e 56 47 41 75 74 68 5f 41 64 64 41 6c 69 61 73 00}  //weight: 2, accuracy: High
        $x_1_2 = "C:\\users\\public\\LOG.txt" ascii //weight: 1
        $x_1_3 = {49 ba f2 0f 10 45 ?? f2 0f 11 01 66 c7 45 ?? 41 ff 8b 45 1f 89 41 08 c6 41 0c e2}  //weight: 1, accuracy: Low
        $x_1_4 = {83 e8 05 c6 45 ?? e9 89 45 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_5 = {ba 99 fb ca 14 b9 67 99 10 31 e8}  //weight: 1, accuracy: High
        $x_1_6 = {ba 6f b6 12 33 b9 6f 44 5e d3 e8}  //weight: 1, accuracy: High
        $x_1_7 = {48 83 ec 20 b9 5a 00 00 00 e8 ?? ?? 00 00 41 b8 2d 00 00 00 48 8d 15 ?? ?? ?? 00 48 8b c8 48 8b d8 e8}  //weight: 1, accuracy: Low
        $x_1_8 = {36 00 00 00 c7 [0-5] 47 00 45 00 c7 [0-5] 54 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

