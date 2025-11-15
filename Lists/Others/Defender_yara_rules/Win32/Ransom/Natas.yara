rule Ransom_Win32_Natas_PAGX_2147957546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Natas.PAGX!MTB"
        threat_id = "2147957546"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Natas"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b7 d7 66 0f be 0c 10 b8 ff 00 00 00 66 33 cf 66 23 c8 0f b6 04 ?? ?? ?? ?? ?? 66 33 c8 47 66 89 0c 53 66 3b 3c f5}  //weight: 3, accuracy: Low
        $x_2_2 = {0f b7 ca 8a 04 08 32 04 f5 ?? ?? ?? ?? 32 c2 42 88 04 39 66 3b 14 f5 ?? ?? ?? ?? 72 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

