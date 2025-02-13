rule Ransom_Win32_Eterniity_YAQ_2147902143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Eterniity.YAQ!MTB"
        threat_id = "2147902143"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Eterniity"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 f7 f1 8b 45 ec 0f be 0c 10 8b 55 e0 0f be 04 16 33 c1 8b 4d f8 8b 51 78 8b 4d e0 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

