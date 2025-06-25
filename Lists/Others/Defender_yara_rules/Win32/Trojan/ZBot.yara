rule Trojan_Win32_ZBot_CRHG_2147847791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZBot.CRHG!MTB"
        threat_id = "2147847791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 05 90 16 d1 14 4d 4f d0 14 c7 05 8c 16 d1 14 c8 11 d0 14 66 89 35 88 16 d1 14 c7 05 a0 16 d1 14 fb 4f d0 14 c7 05 9c 16 d1 14 b4 11 d0 14 66 89 35 98 16 d1 14 c7 05 b0 16 d1 14 b2 50 d0 14 c7 05 ac 16 d1 14 a0 11 d0 14 66 89 35 a8 16 d1 14 c7 05 c0 16 d1 14 a2 51 d0 14 c7 05 bc 16 d1 14 8c 11 d0 14 66 89 35 b8 16 d1 14 c7 05 d0 16 d1 14 92 52 d0 14 c7 05 cc 16 d1 14 78 11 d0 14 66 89 35 c8 16 d1 14 c7 05 e0 16 d1 14 bd 52 d0 14 c7 05 dc 16 d1 14 64 11 d0 14 66 89 35 d8 16 d1 14 c7 05 f0 16 d1 14 f7 52 d0 14 c7 05 ec 16 d1 14 50 11 d0 14 66 89 35 e8 16 d1 14 c7 05 00 17 d1 14 31 53 d0 14 c7 05 fc 16 d1 14 34 11 d0 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZBot_CRTJ_2147849952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZBot.CRTJ!MTB"
        threat_id = "2147849952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a3 80 f0 e0 14 ff d6 68 38 20 e0 14 a3 84 f0 e0 14 ff d6 68 2c 20 e0 14 a3 88 f0 e0 14 ff d6 68 4c 12 e0 14 a3 8c f0 e0 14 ff d6 68 e0 11 e0 14 a3 90 f0 e0 14 ff d6 68 0c 12 e0 14 a3 94 f0 e0 14 ff d6 68 00 12 e0 14 a3 98 f0 e0 14 ff d6 8b 35 28 10 e0 14 68 1c 20 e0 14 ff 35 80 f0 e0 14 a3 9c f0 e0 14 ff d6 68 0c 20 e0 14 ff 35 80 f0 e0 14 a3 a0 f0 e0 14 ff d6 68 f8 1f e0 14 ff 35 80 f0 e0 14 a3 a4 f0 e0 14 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZBot_RDB_2147896556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZBot.RDB!MTB"
        threat_id = "2147896556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 89 45 84 8b 4d 84 03 4d 94 89 4d 84 8b 55 84 8a 02 2a 45 c4 8b 4d 84 88 01 83 7d 8c 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZBot_NZ_2147896909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZBot.NZ!MTB"
        threat_id = "2147896909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d1 8d 4a fe 41 8b d1 8b c8 85 d2 75 15 c1 e2 ?? 33 c0 41 85 e4 74 04 03 c9}  //weight: 5, accuracy: Low
        $x_1_2 = "bLjAQA_.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZBot_CCEK_2147897316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZBot.CCEK!MTB"
        threat_id = "2147897316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 ec 8b 02 33 45 e0 8b 55 ec 89 02 66 c7 45 d4 ?? ?? 8b 45 ec 83 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

