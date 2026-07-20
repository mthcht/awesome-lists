rule Ransom_Win64_Beast_YDQ_2147974138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Beast.YDQ!MTB"
        threat_id = "2147974138"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Beast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {03 45 c4 01 41 08 8b 41 14 03 45 c0 3b 45 c0 89 41 14 1b c0 f7 d8 03 45 b0 01 41 10 8b 41 1c 03 45 bc 3b 45 bc}  //weight: 3, accuracy: High
        $x_1_2 = {88 55 fd 8a 44 35 dc 8b 4d d8 32 c8 88 4c 35 dc 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

