rule Trojan_Win32_TimbreStealer_ZH_2147910872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TimbreStealer.ZH"
        threat_id = "2147910872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TimbreStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 01 00 00 50 [0-32] 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 33 ff 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {40 3d 00 01 00 00 72 f4 [0-8] 33 f6 [0-4] 8a 54 34 ?? 8b c6 83 e0 03 0f b6 ca 0f b6 80}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c7 03 c8 0f b6 f9 8a 44 3c ?? 88 44 34 ?? 46 88 54 3c ?? 81 fe 00 01 00 00 72 d1}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 46 3c 85 c0 74 2f 8b 54 30 7c 85 d2 74 27 8b 44 30 78 85 c0 74 1f 8d 4c 24 1c 51 52 8d 14 30 8b ce e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

