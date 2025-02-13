rule HackTool_Win64_Daoak_A_2147729833_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Daoak.A"
        threat_id = "2147729833"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Daoak"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "software\\classes\\clsid\\{89565276-a714-4a43-912e-978b935edccc}" ascii //weight: 1
        $x_1_2 = "Software\\Classes\\DynamicWrapperX" ascii //weight: 1
        $x_1_3 = {0f b7 0c 48 48 8d 05 ?? ?? ?? ?? 48 01 c1 0f b7 0c 51 48 8d 05 ?? ?? ?? ?? 48 8d 1c 08 48 8b 46 08 48 8b 7d 38 31 c9 ff d3 72 52}  //weight: 1, accuracy: Low
        $x_1_4 = {48 8d 64 24 48 5c ba 00 04 00 00 83 f8 00 74 8e 81 fa 00 04 00 00 74 03 83 c2 02 54 ff 34 24 40 80 cc 08 4c 8d 1d ?? ?? ?? ?? 41 53 49 89 c1 49 89 d0 31 d2 31 c9 48 83 ec 20 e8 ?? ?? ?? ?? 48 8d 64 24 28 5c 31 c0 eb 80}  //weight: 1, accuracy: Low
        $x_1_5 = {eb 03 89 42 2c 83 ff 64 74 05 83 ff 66 75 0a f2 0f 10 85 b0 fc ff ff eb 02 5a 58 85 ff 74 2e 48 8b 4d 58 e3 28 54 ff 34 24 40 80 e4 f0}  //weight: 1, accuracy: High
        $x_1_6 = {8b 47 10 89 85 e8 fc ff ff 0f b6 4b 27 39 c8 74 21 77 0b 3a 43 26 0f 82 24 02 00 00 eb 14 f6 43 24 02 0f 84 18 02 00 00 29 c8 6b c0 18 48 01 c2 89 c8 40 80 e4 f0 0f ba e1 00 73 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

