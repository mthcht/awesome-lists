rule Ransom_Win64_DarkRansom_YBG_2147960446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DarkRansom.YBG!MTB"
        threat_id = "2147960446"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af d8 89 d9 89 c8 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 89 ca 29 c2 d1 ea 01 d0 c1 e8 05 89 c2 89 d0 c1 e0 06 29 d0 29 c1 89 ca 89 d1 48 8b 55 20 48 8b 45 f8 48 01 c2 0f b6 44 0d b0 88 02}  //weight: 10, accuracy: Low
        $x_1_2 = {48 8b 85 08 11 00 00 48 01 d0 0f b6 00 89 ca 31 c2 8b 85 ec 10 00 00 88 54 05 c0}  //weight: 1, accuracy: High
        $x_1_3 = {ba 00 00 00 00 48 f7 75 20 48 8b 45 18 48 01 d0 0f b6 00 31 c8 88 45 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

