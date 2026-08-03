rule Trojan_Win64_SectopRAT_GVA_2147975125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SectopRAT.GVA!MTB"
        threat_id = "2147975125"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SectopRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {cb fa 7a 5f f9 f7 e2 0f 38 fa 39 25 dd 4f 36 99 8a 65 c4 08 ab b8 90 e6 8e 72 56 6a 03 a7 d9 d5 fd 4c 9b 3c 71 27 21 61 10 46 4c b5 72 c7 be b2 75 f5 32 5b 68 7e b2 ed da c3 a0 2e c6 5c 7f 7f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SectopRAT_GVB_2147975126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SectopRAT.GVB!MTB"
        threat_id = "2147975126"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SectopRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a e6 30 db 2d b0 e6 70 8a e2 aa 15 ed a2 0f 75 a7 99 83 09 3c 5d b5 42 36 b1 5c 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

