rule Ransom_Win64_Crytox_AA_2147831987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crytox.AA!MTB"
        threat_id = "2147831987"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crytox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 38 dc 41 10 66 0f 38 dc 41 20 66 0f 38 dc 41 30 66 0f 38 dc 41 40 66 0f 38 dc 41 50 66 0f 38 dc 41 60 66 0f 38 dc 41 70 48 81 c1 80 00 00 00 66 0f 38 dc 01 66 0f 38 dc 41 10 48 83 c1 20 49 3b ca 72 ec 66 41 0f 38 dd 02 41 0f 11 01 49 83 c1 10 4c 3b c0 72 95}  //weight: 1, accuracy: High
        $x_1_2 = {8a 84 31 08 12 00 00 f6 d0 8a 84 30 08 11 00 00 8a d0 d0 c2 32 c2 d0 c2 32 c2 d0 c2 32 c2 d0 c2 32 c2 34 63 88 84 31 08 10 00 00 fe c1 75 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Crytox_E_2147935145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crytox.E"
        threat_id = "2147935145"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crytox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c9 41 8b 34 88 48 03 f2 4d 33 c9 48 33 ?? ac 41 c1 c9 0b 44 03 c8 3a c4 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

