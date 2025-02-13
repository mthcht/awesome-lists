rule TrojanDropper_Win32_Hupigon_2147489241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Hupigon"
        threat_id = "2147489241"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 03 30 00 00 00 c7 43 04 02 00 00 00 c7 43 08 03 00 00 00 33 c0 89 43 0c 33 c0 89 43 10 33 c0 89 43 14 33 c0 89 43 18 68}  //weight: 2, accuracy: High
        $x_2_2 = "GPigeon5_Shared" ascii //weight: 2
        $x_2_3 = "HUIGEZVIP_MUTEX" ascii //weight: 2
        $x_2_4 = "GRAYPIGEON" ascii //weight: 2
        $x_2_5 = {ff ff ff ff 2e 00 00 00 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45}  //weight: 2, accuracy: High
        $x_1_6 = "SEVINFO" ascii //weight: 1
        $x_1_7 = {ff ff ff ff 04 00 00 00 2e 4e 45 57}  //weight: 1, accuracy: High
        $x_1_8 = "SoftWare\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Hupigon_UC_2147600885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Hupigon.UC"
        threat_id = "2147600885"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "112"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {00 43 3a 5c 77 77 77 5c 68 75 69 67 65 7a 69 2e 63 4f 6d 00 00 4f 70 65 4e 00}  //weight: 100, accuracy: High
        $x_10_2 = {53 56 57 8b fa 8b f0 33 db 8a 1e eb 01 4b 83 fb 01 7e 0b 8a 04 1e 2c 3a 74 04 2c 22 75 ef 57 8b c6 ba 01 00 00 00 8b cb e8 ab e0 ff ff 8a 07 84 c0 76 0d 25 ff 00 00 00 80 3c 07 00 75 02 fe 0f 5f 5e 5b c3}  //weight: 10, accuracy: High
        $x_10_3 = {53 56 57 8b fa 8b f0 33 db 8a 1e eb 01 4b 83 fb 01 7e 0f 8a 04 1e 2c 2e 74 08 2c 0c 74 04 2c 22 75 eb 83 fb 01 7e 17 80 3c 1e 2e 75 11 57 8b c6 b9 ff 00 00 00 8b d3 e8 10 e0 ff ff eb 03 c6 07 00 8a 07 84 c0 76 0d 25 ff 00 00 00 80 3c 07 00 75 02 fe 0f 5f 5e 5b c3}  //weight: 10, accuracy: High
        $x_1_4 = {00 43 3a 5c 77 77 77 5c 68 75 69 67 65 7a 69 38 ?? ?? ?? 2e 63}  //weight: 1, accuracy: Low
        $x_1_5 = {00 43 3a 5c 77 77 77 5c 68 75 69 67 65 7a 69 35 ?? ?? ?? 2e 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Hupigon_EJ_2147638802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Hupigon.EJ"
        threat_id = "2147638802"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Hupigon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "taskkill /f /t" ascii //weight: 1
        $x_1_2 = {56 55 53 ff d7 50 8b 44 24 ?? 6a 01 50 e8 ?? ?? 00 00 83 c4 10}  //weight: 1, accuracy: Low
        $x_1_3 = {52 6a 01 53 50 68 02 00 00 80 ff 95 ?? ?? ff ff 3b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

