rule Ransom_Win32_CobaltStrike_2147812409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CobaltStrike!MTB"
        threat_id = "2147812409"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 45 e0 9c 00 00 00 48 8d 05 f4 d9 02 00 48 89 45 e8 48 8b 45 18 8b 10 48 8b 45 10 83 e0 1f 41 b8 01 00 00 00 89 c1 49 d3 e0 4c 89 c0 09 c2}  //weight: 1, accuracy: High
        $x_2_2 = {48 c7 45 d0 5b 01 00 00 48 8d 05 47 dd 02 00 48 89 45 d8 48 8b 45 20 25 ff 01 00 00 48 89 45 f0 48 c7 45 d0 5c 01 00 00 48 8d 05 27 dd 02 00}  //weight: 2, accuracy: High
        $x_2_3 = {48 83 c2 02 4c 8b 04 d0 48 8b 45 f0 83 e0 3f ba 01 00 00 00 89 c1 48 d3 e2 48 89 d1 48 8b 45 f0 48 c1 f8 06 48 89 c2 4c 09 c1 48 8b 45 f8 48 83 c2 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

