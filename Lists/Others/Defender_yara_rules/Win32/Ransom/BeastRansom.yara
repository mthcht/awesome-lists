rule Ransom_Win32_BeastRansom_YAA_2147889522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BeastRansom.YAA!MTB"
        threat_id = "2147889522"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BeastRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 10 14 06 8b c3 c7 44 24 ?? 01 75 1d 10 c7 44 24 ?? 07 10 6a 00 80 74 04}  //weight: 1, accuracy: Low
        $x_10_2 = {03 ca 33 d9 c1 c3 10 03 c3 89 45 ?? 33 c2 8b 55 ?? c1 c0 0c 03 d6 03 c8 33 d9 89 4d ac}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

