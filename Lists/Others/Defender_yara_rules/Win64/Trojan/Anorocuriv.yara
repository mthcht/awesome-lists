rule Trojan_Win64_Anorocuriv_2147752215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Anorocuriv"
        threat_id = "2147752215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Anorocuriv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 [0-16] 53 00 69 00 6e 00 67 00 61 00 70 00 6f 00 72 00 65 00 20 00 68 00 61 00 73 00 20 00 [0-22] 63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 65 00 64 00 20 00 63 00 61 00 73 00 65 00 73 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 76 00 69 00 72 00 75 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 [0-16] 4a 00 75 00 73 00 74 00 20 00 62 00 65 00 63 00 61 00 75 00 73 00 65 00 20 00 73 00 6f 00 6d 00 65 00 6f 00 6e 00 65 00 20 00 77 00 68 00 6f 00 20 00 68 00 61 00 64 00 20 00 74 00 68 00 65 00 20 00 63 00 6f 00 72 00 6f 00 6e 00 61 00 76 00 69 00 72 00 75 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Anorocuriv_2147752216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Anorocuriv!MTB"
        threat_id = "2147752216"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Anorocuriv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 69 00 6e 00 67 00 61 00 70 00 6f 00 72 00 65 00 20 00 68 00 61 00 73 00 20 00 [0-6] 20 00 63 00 6f 00 6e 00 66 00 69 00 72 00 6d 00 65 00 64 00 20 00 63 00 61 00 73 00 65 00 73 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 76 00 69 00 72 00 75 00 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = {54 00 68 00 65 00 20 00 72 00 65 00 73 00 74 00 72 00 69 00 63 00 74 00 69 00 6f 00 6e 00 73 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 61 00 6e 00 20 00 74 00 72 00 61 00 76 00 65 00 6c 00 20 00 74 00 6f 00 20 00 74 00 68 00 65 00 20 00 55 00 53 00 20 00 66 00 72 00 6f 00 6d 00 20 00 [0-4] 20 00 45 00 75 00 72 00 6f 00 70 00 65 00 61 00 6e 00 20 00 63 00 6f 00 75 00 6e 00 74 00 72 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

