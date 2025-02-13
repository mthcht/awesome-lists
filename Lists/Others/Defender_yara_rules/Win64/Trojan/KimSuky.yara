rule Trojan_Win64_KimSuky_AT_2147920543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/KimSuky.AT!MTB"
        threat_id = "2147920543"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "KimSuky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 66 75 44 76 73 73 66 6f 75 45 6a 73 66 64 75 70 73 7a 42 00 00 00 00 47 6a 6d 66 55 6a 6e 66 55 70 4d 70 64 62 6d 47 6a 6d 66 55 6a 6e 66 00 47 6a 6d 66 55 6a 6e 66 55 70 54 7a 74 75 66 6e}  //weight: 1, accuracy: High
        $x_1_2 = {b8 01 00 00 00 48 85 db 48 0f 44 d8 4c 8b c7 33 d2 4c 8b cb}  //weight: 1, accuracy: High
        $x_1_3 = {ff 41 80 ff 49 74 44 41 80 ff 68 74 35 41 80 ff 6c 74 14 41 80 ff 77 0f 85 f5 fb ff ff 41 0f ba ee 0b e9 eb fb ff ff 80 3f 6c 75 0d 48 ff c7 41 0f ba ee 0c e9 d9 fb ff ff 41 83 ce 10 e9 d0 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

