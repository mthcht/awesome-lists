rule Ransom_Win32_Acepy_MKV_2147935319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Acepy.MKV!MTB"
        threat_id = "2147935319"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Acepy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 04 89 45 e4 8b 45 f0 8b 4d e4 31 d2 f7 f1 8b 45 0c 01 d0 8b 4d e8 0f be 09 0f be 10 31 d1 8b 45 ?? 88 08 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

