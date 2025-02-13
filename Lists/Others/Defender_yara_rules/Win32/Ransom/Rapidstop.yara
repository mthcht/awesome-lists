rule Ransom_Win32_Rapidstop_YAA_2147911612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rapidstop.YAA!MTB"
        threat_id = "2147911612"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapidstop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 0b 8b 83 a4 00 00 00 33 43 7c 33 43 54 33 43 2c 33 43 04 89 4d ac 8b 8b a8 00 00 00 33 8b 80 00 00 00 33 4b 58 33 4b 30 33 4b 08 89 45 b0}  //weight: 1, accuracy: High
        $x_1_2 = {f7 f9 33 74 d5 ?? 33 7c d5 b0 8b 55 fc 8b c2 31 30 8d 40 28 31 78 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

