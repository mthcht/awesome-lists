rule Trojan_Win64_Blackwidow_MLV_2147935557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blackwidow.MLV!MTB"
        threat_id = "2147935557"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blackwidow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 ?? c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 49 f7 f1 c5 d5 fd f5 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 c5 cd 75 f6 45 8a 14 10 c5 fd fd c6 c5 f5 fd cf c5 fd 67 c0}  //weight: 5, accuracy: Low
        $x_4_2 = {dd 61 e1 c5 fd 70 f8 4e c5 fd 62 c3 c5 e5 6a dc 48 89 c8 c4 e3 fd 00 f6 ?? c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 48 81 f9 d3 25 1c 00 0f 86}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

