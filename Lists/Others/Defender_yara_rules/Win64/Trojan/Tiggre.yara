rule Trojan_Win64_Tiggre_CMM_2147783651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tiggre.CMM!MTB"
        threat_id = "2147783651"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tiggre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 49 02 bf ff ff ff ff bb ff ff ff ff d3 e3 89 d9 31 f9 81 e1 46 52 5d 39 81 e3 b9 ad a2 c6 09 cb 81 f3 b9 ad a2 36 44 31 df 31 df 21 df c1 e7 04 44 8d 3c 2f}  //weight: 1, accuracy: High
        $x_1_2 = {41 8a 49 01 be ff ff ff ff d3 e6 31 f7 b8 db bb 27 5f 21 c7 81 e6 24 44 d8 a0 09 fe 44 31 de 31 c6 44 21 de 41 0f b6 09 d3 e6 49 8b 41 18 49 8b 79 28}  //weight: 1, accuracy: High
        $x_1_3 = "oqcazu737w7m.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

