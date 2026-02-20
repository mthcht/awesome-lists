rule Trojan_Win64_Starter_ASA_2147953213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Starter.ASA!MTB"
        threat_id = "2147953213"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 c2 8b 45 fc 48 98 48 8d 0c ?? ?? ?? ?? ?? 48 8b 45 18 48 01 c8 8b 00 48 98 83 e0 3f 0f b6 44 05 b0 88 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Starter_ASR_2147963430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Starter.ASR!MTB"
        threat_id = "2147963430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b f8 33 c0 b9 08 02 00 00 f3 aa 4c 8d 4d 30 4c 8d 05 dd 97 00 00 ba 04 01 00 00 48 8d 8d 60 02 00 00}  //weight: 1, accuracy: High
        $x_2_2 = {48 8b f8 33 c0 b9 00 fa 00 00 f3 aa 4c 8d 8d 60 02 00 00 4c 8d 05 ca 97 00 00 ba 00 7d 00 00 48 8d 8d 90 04 00 00}  //weight: 2, accuracy: High
        $x_3_3 = {48 8b f8 33 c0 b9 fc 7f 00 00 f3 aa 4c 8d 05 6e 9c 00 00 ba fe 3f 00 00 48 8d 8d b0 fe 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

