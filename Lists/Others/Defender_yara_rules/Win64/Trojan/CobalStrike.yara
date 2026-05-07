rule Trojan_Win64_CobalStrike_ARAX_2147944891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobalStrike.ARAX!MTB"
        threat_id = "2147944891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobalStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 32 ca 44 8b 54 24 30 41 ff c2 41 88 09 49 ff c1 44 89 54 24 30 4c 89 4c 24 28 41 8d 04 32 3b c3 0f 8c 79 fc ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobalStrike_ARA_2147964200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobalStrike.ARA!MTB"
        threat_id = "2147964200"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobalStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 d9 48 89 f7 83 e1 03 48 c1 e1 03 48 d3 ff 31 f8 88 44 1a 08 48 ff c3 e9}  //weight: 2, accuracy: High
        $x_2_2 = {4c 89 c1 83 e1 03 48 c1 e1 03 49 d3 fe 44 31 f0 42 88 44 02 08 49 ff c0 e9}  //weight: 2, accuracy: High
        $x_2_3 = {83 e1 03 48 c1 e1 03 49 d3 f9 48 8d 4c 24 50 44 31 c8 42 88 44 3a 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobalStrike_TMC_2147968500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobalStrike.TMC!MTB"
        threat_id = "2147968500"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobalStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 39 c2 74 2c 46 0f b6 0c 01 45 8d 51 bf 45 89 cb 41 80 cb 20 41 80 fa 1a 45 0f b6 d3 45 0f 43 d1 44 6b c8 21 41 0f b6 c2 44 01 c8 49 ff c0 eb cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobalStrike_KLHB_2147968601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobalStrike.KLHB!MTB"
        threat_id = "2147968601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobalStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f3 0f 6f 04 06 66 0f ef c1 0f 11 04 03 48 83 c0 10 48 39 d0 ?? ?? 89 f8 83 e0 f0 40 f6 c7 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

