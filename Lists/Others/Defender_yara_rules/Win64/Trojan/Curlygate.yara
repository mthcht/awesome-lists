rule Trojan_Win64_Curlygate_YBB_2147975360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Curlygate.YBB!MTB"
        threat_id = "2147975360"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 35 f6 f6 e9 ?? ?? ?? ?? 24 89 81 d4 01 00 00 e9 7b fb ff ff 8b 44 24 08 35 ?? ?? ?? ?? 48 8b 0c 24 89 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Curlygate_YBC_2147975361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Curlygate.YBC!MTB"
        threat_id = "2147975361"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 48 8b 45 f0 48 01 d0 8b 4d f8 48 8b 55 f0 48 01 ca 0f b6 00 88 02 8b 45 e0 2b 45 f8 83 e8 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Curlygate_YPU_2147976163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Curlygate.YPU!MTB"
        threat_id = "2147976163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 01 2b 4c 24 ?? 89 c9 8a 04 08 48 8b 4c 24 ?? 8b 54 24 ?? 88 04 11 8a 44 24 ?? 48 8b 4c 24 ?? 8b 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Curlygate_YPQ_2147976164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Curlygate.YPQ!MTB"
        threat_id = "2147976164"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 89 c2 41 80 ca 20 41 80 f9 1a 45 0f b6 ca 45 0f 43 c8 4c 8d 41 01 41 80 f9 6e}  //weight: 1, accuracy: High
        $x_1_2 = {41 80 fa 76 75 [0-4] 4c 8d 49 02 49 39 d1}  //weight: 1, accuracy: Low
        $x_1_3 = {41 80 fa 69 0f 85 [0-4] 4c 8d 49 03 49 39 d1}  //weight: 1, accuracy: Low
        $x_1_4 = {41 80 fa 64 0f 85 [0-4] 4c 8d 49 04 49 39 d1}  //weight: 1, accuracy: Low
        $x_1_5 = {41 80 fa 69 0f 85 [0-4] 4c 8d 49 05 49 39 d1}  //weight: 1, accuracy: Low
        $x_1_6 = {45 0f b6 ca 44 0f 43 c9 41 80 f9 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Curlygate_YBA_2147976387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Curlygate.YBA!MTB"
        threat_id = "2147976387"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Curlygate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 0c 24 89 81 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 44 24 ?? 35 ?? ?? ?? ?? 48 8b 0c 24 89 81 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 44 24 ?? 35 ?? ?? ?? ?? 48 8b 0c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

