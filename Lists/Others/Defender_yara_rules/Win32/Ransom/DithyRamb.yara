rule Ransom_Win32_DithyRamb_A_2147921614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DithyRamb.A!MTB"
        threat_id = "2147921614"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DithyRamb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 89 4d fc 0f be 45 08 35 aa 00 00 00 8b e5 5d c2 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 e4 3b 45 d0 74 18 8b 4d e4 89 4d d8 8b 55 d8 0f be 02 35 aa 00 00 00 8b 4d d8 88 01}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 fc 3b 55 f0 74 19 8b 45 fc 89 45 f4 8b 4d f4 0f be 11 81 f2 aa 00 00 00 8b 45 f4 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

