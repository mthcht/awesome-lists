rule Ransom_Win64_Proton_MA_2147852270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Proton.MA!MTB"
        threat_id = "2147852270"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Proton"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {dd fe 7f fb 48 89 5c 24 08 08 7c 24 10 55 48 8d 6c 24 a9 48 81 ec 90 00 00 c6 45 e7 7d 9a cd f6 06 e8 79 0e e9 71 ea 72 eb ec 28 fe 7b 9e a7 1e}  //weight: 2, accuracy: High
        $x_2_2 = {6b c8 1a b8 09 04 02 81 f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 bf 43 ec ff 1f 03 d0 6b c2 7f 2b c8 83 c1 7f 35 42 88 82 49 ff c0 dc df fe ff 49 83 f8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Proton_A_2147960637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Proton.A"
        threat_id = "2147960637"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Proton"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 42 39 39 31 33 36 39 2d 37 43 37 43 2d 34 37 41 41 2d 41 38 31 45 2d 45 46 36 45 44 31 46 35 45 32 34 43 00}  //weight: 1, accuracy: High
        $x_1_2 = {3c 00 42 00 41 00 43 00 4b 00 55 00 50 00 5f 00 45 00 4d 00 41 00 49 00 4c 00 3e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {3c 00 49 00 44 00 3e 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 5b 00 3c 00 45 00 4d 00 41 00 49 00 4c 00 3e 00 5d 00 3c 00 45 00 58 00 54 00 45 00 4e 00 53 00 49 00 4f 00 4e 00 3e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

