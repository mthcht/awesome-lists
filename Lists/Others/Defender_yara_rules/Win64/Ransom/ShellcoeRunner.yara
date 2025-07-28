rule Ransom_Win64_ShellcoeRunner_PCC_2147947608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ShellcoeRunner.PCC!MTB"
        threat_id = "2147947608"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcoeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 98 0f b6 44 05 a0 8b 95 ?? 07 00 00 48 63 ca 48 8b 95 ?? 07 00 00 48 01 ca 32 85 ?? 07 00 00 88 02 83 85 ?? 07 00 00 01 8b 85 ?? 07 00 00 3d 1f 08 00 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

