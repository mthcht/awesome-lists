rule Ransom_Win64_Nokonoko_ZA_2147843477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokonoko.ZA"
        threat_id = "2147843477"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {41 0f be 10 4d 8d 40 01 8b c8 c1 e8 ?? 48 33 d1 0f b6 ca 41 33 04 8f 49 83 e9 01 75 e3 f7 d0 3b c6 74 27}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Nokonoko_ZB_2147843479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nokonoko.ZB"
        threat_id = "2147843479"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nokonoko"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba e2 08 85 99 48 8d 0d d8 3a 00 00 e8 cb 2c 00 00 45 33 c9 45 33 c0 48 8b d3 49 8b cc ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {ba d0 03 5c 09}  //weight: 1, accuracy: High
        $x_1_3 = {ba e2 08 85 99}  //weight: 1, accuracy: High
        $x_1_4 = {ba 12 56 e9 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

