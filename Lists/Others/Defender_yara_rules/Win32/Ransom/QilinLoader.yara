rule Ransom_Win32_QilinLoader_MKV_2147905649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/QilinLoader.MKV!MTB"
        threat_id = "2147905649"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "QilinLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ea 89 5c 24 4c 8b 4c 24 34 89 44 24 54 8b 44 24 24 89 74 24 50 8b 00 89 5c 24 28 89 44 24 30 0f b7 40 06 66 89 44 24 ?? 0f b7 44 24 2c 83 c1 01 83 c7 28 39 c1 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

