rule Trojan_Win64_Exnet_ARR_2147962785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Exnet.ARR!MTB"
        threat_id = "2147962785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {8a 44 24 0c 30 44 0c 0d 41 83 f9}  //weight: 12, accuracy: High
        $x_8_2 = {c6 44 24 5f 00 50 33 c0 0f 9b c0 52 33 d0 c1 e2 ?? 92 5a 0b c1}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Exnet_ARR_2147962785_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Exnet.ARR!MTB"
        threat_id = "2147962785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {8b 4c 24 30 8b d0 81 f2 ?? ?? ?? ?? 83 c0 ?? 03 d1 89 54 24 30}  //weight: 11, accuracy: Low
        $x_9_2 = {0f be c9 48 8d 40 ?? 41 33 c8 44 69 c1 ?? ?? ?? ?? 0f b6 08 44 33 c2}  //weight: 9, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Exnet_A_2147980181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Exnet.A!MTB"
        threat_id = "2147980181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Exnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 0f b6 84 31 b0 49 00 00 48 8d 49 01 34 9e 88 84 0d 3f 02 00 00 49 2b d7 75 e5 48 8d 95 30 02 00 00 49 8b c8 ff 15 ?? ?? ?? ?? 4c 8b 74 24 50 48 8d 95 30 02 00 00 b9 40 00 00 00 0f 1f 40 00 c6 02 00 48 8d 52 01 41 2b cf 75 f4}  //weight: 5, accuracy: Low
        $x_1_2 = "inject: OK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

