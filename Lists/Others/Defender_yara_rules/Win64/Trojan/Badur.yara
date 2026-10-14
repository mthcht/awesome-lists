rule Trojan_Win64_Badur_NB_2147980224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Badur.NB!MTB"
        threat_id = "2147980224"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Badur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 0d 68 36 08 00 48 89 8c 24 40 01 00 00 48 89 84 24 48 01 00 00 48 8d 05 fb df 10 00 bb a9 00 00 00 48 8d 8c 24 10 01 00 00 bf 04 00 00 00 48 89 fe}  //weight: 2, accuracy: High
        $x_2_2 = {48 8d 0d 7d 52 0f 00 48 89 8c 24 b0 00 00 00 48 8d 84 24 a0 00 00 00 bb 02 00 00 00 48 89 d9 e8 a8 87 e8 ff 48 89 44 24 48 48 89 5c 24 38 31 c0 48 8b 5c 24 60 48 8b 4c 24 40 e8 4d 82 df ff 48 89 df 48 89 ce 41 b8 a4 01 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {4c 8d 0d e1 51 0f 00 4c 89 8c 24 c0 00 00 00 48 c7 84 24 d8 00 00 00 10 00 00 00 4c 8d 0d c7 76 0f 00 4c 89 8c 24 d0 00 00 00 48 c7 84 24 e8 00 00 00 06 00 00 00 4c 8d 0d 9d 42 0f 00 4c 89 8c 24 e0 00 00 00 48 c7 84 24 f8 00 00 00 05 00 00 00 4c 8d 0d 6a 40 0f 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

