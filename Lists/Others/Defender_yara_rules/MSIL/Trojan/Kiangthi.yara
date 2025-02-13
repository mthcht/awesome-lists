rule Trojan_MSIL_Kiangthi_MBCU_2147846731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kiangthi.MBCU!MTB"
        threat_id = "2147846731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kiangthi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 2d 2e 26 16 2d 33 18 25 2c 03 2d 2a 17 25 2c e8 8d ?? 00 00 01 25 16 72 45 00 00 70 a2 15 2d 1b 26 2a 16 2c 1c 26 26}  //weight: 1, accuracy: Low
        $x_1_2 = "EBSDCBRS.dll" wide //weight: 1
        $x_1_3 = {57 3f a2 1f 09 0f 00 00 00 3a 00 13 00 06 00 00 01 00 00 00 ec 00 00 00 bf 00 00 00 7c 02 00 00 c8 04 00 00 da 03 00 00 1b 00 00 00 37 02 00 00 39 00 00 00 ee}  //weight: 1, accuracy: High
        $x_1_4 = {1e 2d 12 26 26 2b e7 28 73 00 00 06 2b ea 28 34 00 00 0a 2b e9 6f 57 00 00 0a 2b e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

