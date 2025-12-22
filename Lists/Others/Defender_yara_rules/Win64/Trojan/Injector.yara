rule Trojan_Win64_Injector_CD_2147731260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.CD"
        threat_id = "2147731260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 0f b6 ca 45 0f b6 c2 41 8d 41 fc 48 63 d0 0f b6 04 0a 41 30 04 08 45 8d 41 01 41 8d 41 fd 48 63 d0 0f b6 04 0a 41 30 04 08 41 8d 41 fe 48 63 d0 45 8d 41 02 0f b6 04 0a 41 30 04 08 41 8d 41 ff 48 63 d0 45 8d 41 03 0f b6 04 0a 41 30 04 08 41 80 c2 fc 75 aa}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 17 48 8b 5c 24 08 0f b6 c2 24 01 f6 d8 0f b6 41 1d 45 1a c0 d0 ea 41 80 e0 8d 44 32 c2 42 0f b6 14 18 0f b6 41 1e 41 32 d0 30 11 44 88 07 48 8b 7c 24 10 42 0f b6 04 18 30 41 01 0f b6 41 1f 42 0f b6 04 18 30 41 02 0f b6 41 1c 42 0f b6 04 18 30 41 03 c3}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 5c 24 08 44 0f b6 02 48 8d 1d ?? ?? ?? ?? 0f b6 41 1d 4c 8d 59 04 4c 8b ca 41 b2 04 0f b6 04 18 41 32 c0 30 01 0f b6 41 1e 0f b6 04 18 30 41 01 0f b6 41 1f 0f b6 04 18 30 41 02 0f b6 41 1c 0f b6 04 18 30 41 03 41 0f b6 c0 c0 e8 07 45 02 c0 0f b6 c0 6b d0 1b 41 32 d0 41 88 11 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_GPKL_2147927074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.GPKL!MTB"
        threat_id = "2147927074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 44 8b ca 0f 1f 40 00 6b c9 21 4d 8d 40 01 41 33 c9 45 0f be 48 ff 45 85 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_LM_2147946819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.LM!MTB"
        threat_id = "2147946819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 0f b6 09 41 ff c0 83 e1 0f 4a 0f be 84 31 60 ad 76 00 42 8a ?? ?? ?? ?? ?? ?? 4c 2b c8 41 8b 51 fc d3 ea ff ca 45 3b c3}  //weight: 10, accuracy: Low
        $x_15_2 = {4a 0f be 84 19 60 ad 76 00 42 8a ?? ?? ?? ?? ?? ?? 48 2b d0 8b 42 fc 4c 8d 42 04 d3 e8 49 89 51 08 41 89 41 20 8b 02 4d 89 41 08 41 89 41 24 49 83 ea 01}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_KK_2147948308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.KK!MTB"
        threat_id = "2147948308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 33 c1 48 8b d0 8b c0 48 c1 ea ?? 48 33 d0 41 83 e0 ?? 48 8b c2 49 33 c1 41 be ?? 00 00 00 48 35 ?? ?? ?? ?? 41 8b ce 48 c1 e8 08 41 2a c8 48 33 c2}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_NM_2147951188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.NM!MTB"
        threat_id = "2147951188"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 0d 42 e5 09 00 bf 01 00 00 00 ?? b8 e0 f9 ff 48 85 db 76 5c 48 89 44 ?? 28 48 c7 44 ?? 20 00 00 00 00 48 8b 54 ?? 28 48 89 54 ?? 20 48 8b 05 ac 83 1a 00 48 8d 5c ?? 20 b9 01 00 00 00 48 89 cf ?? e2 76 fb ff 66}  //weight: 2, accuracy: Low
        $x_1_2 = {48 8d 05 62 f4 08 00 66 ?? ?? 3b 08 f6 ff 48 8b 8c ?? a8 00 00 00 48 89 48 08 48 8b 8c ?? b0 00 00 00 48 89 48 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_AHJ_2147951991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.AHJ!MTB"
        threat_id = "2147951991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 63 8d c4 fe ff ff 48 8b d1 48 c1 e2 08 48 03 d1 0f b7 8d c4 fe ff ff 48 33 ca 48 33 c8}  //weight: 10, accuracy: High
        $x_30_2 = {48 03 d0 48 63 85 1c ff ff ff 48 03 d0 48 63 85 18 ff ff ff 48 03 d0 48 03 95 10 ff ff ff 48 33 95 28 ff ff ff 48 87 11 48}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_PGIN_2147954056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.PGIN!MTB"
        threat_id = "2147954056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 61 79 6c 6f 61 64 20 63 6f 70 69 65 64 20 74 6f 20 6c 6f 63 61 6c 20 6d 61 70 70 69 6e 67 3a 20 30 78 25 70 0a}  //weight: 2, accuracy: High
        $x_2_2 = {53 65 63 74 69 6f 6e 20 6d 61 70 70 65 64 20 69 6e 74 6f 20 72 65 6d 6f 74 65 20 70 72 6f 63 65 73 73 20 61 74 3a 20 30 78 25 70 0a}  //weight: 2, accuracy: High
        $x_1_3 = "Injection completed successfully!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_NA_2147954600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.NA!MTB"
        threat_id = "2147954600"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 72 08 33 ff 4c 03 ce 45 33 c0 8b d5 41 0f b6 09 83 e1 0f 4a 0f be 84 31 48 2c 03 00 42 8a 8c 31 58 2c 03 00 4c 2b c8 45 8b 59 fc 41 d3 eb 45 85 db 74 6c}  //weight: 2, accuracy: High
        $x_1_2 = {41 0f b6 09 41 ff c0 83 e1 0f 4a 0f be 84 31 48 2c 03 00 42 8a 8c 31 58 2c 03 00 4c 2b c8 41 8b 51 fc d3 ea ff ca 45 3b c3 72 a5 45 85 c0 0f 44 d5 8b c2 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXA_2147956727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXA!MTB"
        threat_id = "2147956727"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {ff c0 48 98 48 c7 44 24 ?? ?? ?? ?? ?? 4c 8b c8 4c 8d 45 50 48 8b 95 d8 01 00 00 48 8b 8d b8 01 00 00 ff 15}  //weight: 15, accuracy: Low
        $x_10_2 = {48 6b c0 01 48 8b 8d 18 04 00 00 48 8b 04 01 48 89 45 08 b8 ?? ?? ?? ?? 48 6b c0 ?? 48 8b 8d 18 04 00 00 48 8b 04 01}  //weight: 10, accuracy: Low
        $x_1_3 = "DLL Inject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXB_2147957469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXB!MTB"
        threat_id = "2147957469"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 44 24 38 0f b7 40 14 48 8b 4c 24 38 48 8d 44 01 18 48 63 4c 24 30 48 6b c9 ?? 48 03 c1 48 89 44 24 48}  //weight: 10, accuracy: Low
        $x_1_2 = "Injected sucessfully" ascii //weight: 1
        $x_1_3 = "AgentService.exe" ascii //weight: 1
        $x_1_4 = "Hook detect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_LMB_2147957708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.LMB!MTB"
        threat_id = "2147957708"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 63 44 24 24 33 d2 b9 10 00 00 00 48 f7 f1 48 8b c2 0f be 44 04 7c 48 63 4c 24 24 48 8b 54 24 58 0f b6 0c 0a 33 c8 8b c1 48 63 4c 24 24 48 8b 54 24 58 88 04 0a}  //weight: 20, accuracy: High
        $x_10_2 = {48 8b 4c 24 40 48 03 c8 48 8b c1 48 89 44 24 58 c7 44 24 24 00 00 00 00 eb ?? 8b 44 24 24 ff c0 89 44 24 24 48 8b 44 24 30 8b 40 10 39 44 24 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXC_2147958668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXC!MTB"
        threat_id = "2147958668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {48 89 44 24 68 c5 fe 6f 44 24 50 c5 fd ef 4c 24 30 c5 fe 7f 4c 24 30 c5 f8 77}  //weight: 15, accuracy: High
        $x_10_2 = {48 8b 44 24 20 48 89 44 24 48 48 89 4c 24 20 48 8d 4c 24 30 48 8b 44 24 20 48 89 54 24 20 33 d2 48 89 44 24 50 48 8b 44 24 20 4c 89 44 24 20 48 89 44 24 58}  //weight: 10, accuracy: High
        $x_1_3 = "chrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injector_SXD_2147959940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injector.SXD!MTB"
        threat_id = "2147959940"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {44 32 d6 41 fe c2 c1 64 24 08 ?? 41 80 f2 86 48 c7 44 24 00 ?? ?? ?? ?? 41 d0 ca 48 c1 74 24 08 ?? 66 81 6c 24 01 ?? ?? 48 c1 4c 24 07 ?? 41 80 f2 32 48 ff 44 24 08 c1 7c 24 0b}  //weight: 20, accuracy: Low
        $x_10_2 = {41 fe cb 41 32 f3 f7 5c 24 ?? 48 c1 4c 24 ?? ?? 4e 8d 5c 1c ?? 41 88 0b 0f 99 44 24 ?? 48 8d 64 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

