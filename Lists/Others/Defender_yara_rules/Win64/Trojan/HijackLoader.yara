rule Trojan_Win64_HijackLoader_GPA_2147957225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HijackLoader.GPA!MTB"
        threat_id = "2147957225"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {74 3e 48 8b 84 24 ?? ?? 00 00 8a 08 48 8b 84 24 ?? ?? 00 00 88 08 48 8b 84 24 ?? ?? 00 00 48 83 c0 01 48 89 84 24 ?? ?? 00 00 48 8b 84 24 ?? ?? 00 00 48 83 c0 01 48 89 84 24 ?? ?? 00 00 eb a5}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_HijackLoader_ARAC_2147968009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HijackLoader.ARAC!MTB"
        threat_id = "2147968009"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 84 24 90 01 00 00 0f b6 10 48 8b 84 24 88 01 00 00 88 10 48 83 84 24 88 01 00 00 01 48 83 84 24 90 01 00 00 01 48 8b 84 24 98 01 00 00 48 8d 50 ff 48 89 94 24 98 01 00 00 48 85 c0 0f 95 c0 84 c0 75 bb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_HijackLoader_ARAC_2147968009_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HijackLoader.ARAC!MTB"
        threat_id = "2147968009"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 84 24 98 01 00 00 0f b6 10 48 8b 84 24 b8 01 00 00 88 10 48 83 84 24 b8 01 00 00 01 48 83 84 24 98 01 00 00 01 48 8b 84 24 a8 01 00 00 48 8d 50 ff 48 89 94 24 a8 01 00 00 48 85 c0 0f 95 c0 84 c0 75 bb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_HijackLoader_ARAD_2147968350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HijackLoader.ARAD!MTB"
        threat_id = "2147968350"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 29 41 8b d2 48 8b 05 cb 6e 24 00 48 8d 52 01 41 ff c0 0f be 4c 10 ff 66 41 89 4c 54 fe 48 8b 05 b2 6e 24 00 44 38 14 10 75 da}  //weight: 2, accuracy: High
        $x_2_2 = {74 22 48 2b de 49 03 dd 0f 1f 40 00 0f 1f 84 00 00 00 00 00 0f b6 04 0b 88 01 48 8d 49 01 49 83 e8 01 75 f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_HijackLoader_ARAE_2147968849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HijackLoader.ARAE!MTB"
        threat_id = "2147968849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 05 d5 df 0b 00 48 8d 52 01 41 ff c0 0f be 4c 10 ff 66 41 89 4c 54 fe 48 8b 05 bc df 0b 00 44 38 14 10 75 da}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_HijackLoader_ARAF_2147969502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HijackLoader.ARAF!MTB"
        threat_id = "2147969502"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 25 41 8b d2 48 8b 05 95 66 24 00 41 ff c0 0f be 0c 10 66 89 0c 56 48 ff c2 48 8b 05 80 66 24 00 44 38 14 10 75 de}  //weight: 2, accuracy: High
        $x_2_2 = {74 14 48 2b df 49 03 de 8a 04 0b 88 01 48 ff c1 49 83 e8 01 75 f2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_HijackLoader_AB_2147972952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/HijackLoader.AB!MTB"
        threat_id = "2147972952"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "HijackLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {85 c0 74 20 83 bd 38 07 00 00 02 75 17 80 bd 30 07 00 00 4d 75 0e 80 bd 31 07 00 00 5a 75 05 41 8b df eb 02 33 db 48 8b cf ff 15 d8 25 00 00 85 db 74 5a bb 70 00}  //weight: 6, accuracy: High
        $x_6_2 = {48 8d 05 d5 f7 ff ff 89 5c 24 70 48 89 45 80 48 8d 4c 24 70 48 8d 45 50 44 89 7c 24 74 48 89 45 88 48 8d 85 60 01 00 00 48 89 45 98 48 8d 05 b5 f7 ff ff 48 89 45 b8 44 89 7d a0 ff 15 f7 25 00 00 e9 a3}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

