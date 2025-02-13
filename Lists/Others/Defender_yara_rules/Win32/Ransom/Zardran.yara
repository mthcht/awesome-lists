rule Ransom_Win32_Zardran_A_2147754147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zardran.A!MTB"
        threat_id = "2147754147"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zardran"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 89 34 24 33 f6 0b b3 ?? ?? ?? 00 8b c6 5e 83 f8 00 76 17 6a 40 68 00 10 00 00 53 83 24 24 00 01 04 24 6a 00 ff 93 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 06 46 85 c0 74 36 bb 00 00 00 00 23 d3 21 5d fc ff 75 fc 81 04 24 08 00 00 00 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 83 7d fc 00 74 02 eb ed 6a 00 89 3c 24 2b ff 0b fb 8b c7 5f aa 49 75 be}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 1c 30 6a 00 89 34 24 2b f6 0b 75 ec 8b d6 5e d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d e8 75 c1 6a 00 89 34 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

