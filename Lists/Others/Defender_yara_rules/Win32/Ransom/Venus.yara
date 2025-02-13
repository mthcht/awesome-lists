rule Ransom_Win32_Venus_A_2147835088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Venus.A!MTB"
        threat_id = "2147835088"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Venus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 08 50 0f b7 87 ?? ?? 00 00 83 f0 07 50 0f b7 87 ?? ?? 00 00 33 c1 83 f0 05 50 0f b7 87 ?? ?? 00 00 33 c1 83 f0 06 50 ff 75 fc 68}  //weight: 1, accuracy: Low
        $x_1_2 = {58 8b 4d fc b8 ?? ?? ?? ?? 8b 75 08 f7 e1 03 f1 c1 ea 04 8d 04 52 c1 e0 03 2b c8 8a 81 ?? ?? ?? ?? 30 06 50 33 c0 58 8b 45 fc 40 89 45 fc 3b 45 0c 7c}  //weight: 1, accuracy: Low
        $x_1_3 = ".goodgame" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

