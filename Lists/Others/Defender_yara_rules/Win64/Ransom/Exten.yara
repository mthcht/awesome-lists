rule Ransom_Win64_Exten_YAB_2147951989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Exten.YAB!MTB"
        threat_id = "2147951989"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Exten"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 89 c1 c1 e9 0f c1 e8 06 01 c8 89 c1 c1 e1 07 29 c8 01 d0 05 ?? ?? ?? ?? 04 7f 0f b6 c0 8d 0c 40 c1 e9 08 89 c2 28 ca d0 ea 00 ca c0 ea}  //weight: 1, accuracy: Low
        $x_1_2 = {29 ca 0f bf ca 69 c9 ?? ?? ?? ?? c1 e9 10 01 d1 0f b7 c9 41 89 c8 41 c1 e8 0f c1 e9 06 44 01 c1 41 89 c8 41 c1 e0 07 44 29 c1 01 d1 80 c1 7f 0f b6 c9}  //weight: 1, accuracy: Low
        $x_5_3 = ".EXTEN" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

