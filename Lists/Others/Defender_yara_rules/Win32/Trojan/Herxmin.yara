rule Trojan_Win32_Herxmin_A_2147680307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Herxmin.A"
        threat_id = "2147680307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Herxmin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":yeahyeahyeah@mine.pool-x.eu" ascii //weight: 1
        $x_1_2 = {79 65 61 68 79 65 61 68 79 65 61 68 [0-8] 62 61 72 62 69 65 2e 31}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 07 0f b7 1e ff 4d 08 ff 4d fc 83 c6 02 89 45 f8 83 c7 02}  //weight: 1, accuracy: High
        $x_1_4 = {89 5e 78 89 5e 7c 88 9e 80 00 00 00 68 ?? ?? ?? 00 8b ce c6 ?? ?? 06 c7 46 34 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = "coin-miner" ascii //weight: 1
        $x_1_6 = {50 53 53 6a 1a 53 ff 15 ?? ?? ?? ?? 68 04 01 00 00 8d 85 ?? ?? ?? ?? 53 50 e8 ?? ?? ?? ?? 6a 25 58 66 89 45}  //weight: 1, accuracy: Low
        $x_1_7 = {68 41 00 00 80 ff 15 ?? ?? ?? ?? 8b 85 64 ff ff ff 3b c3 74 05 8d 70 50 eb 02 33 f6 05 d8 02 00 00 50 8b ce 89 86 00 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

