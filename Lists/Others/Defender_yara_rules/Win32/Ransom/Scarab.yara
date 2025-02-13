rule Ransom_Win32_Scarab_PA_2147745757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Scarab.PA!MTB"
        threat_id = "2147745757"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Scarab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 46 85 c0 74 ?? bb 00 00 00 00 23 d3 21 5d fc ff 75 fc 81 04 24 08 00 00 00 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 ?? 55 33 2c 24 33 eb 83 e0 00 03 c5 5d aa 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {a4 49 75 fc 33 c9 0b 0c 24 83 c4 04 33 ff 8b 3c 24 83 ec fc 6a 00 89 04 24 33 c0 33 c7 8b f0 58 56 29 34 24 31 1c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

