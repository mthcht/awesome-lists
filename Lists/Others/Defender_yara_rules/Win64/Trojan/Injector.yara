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

