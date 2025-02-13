rule Ransom_Win32_Djvu_RPO_2147831921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Djvu.RPO!MTB"
        threat_id = "2147831921"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Djvu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d f0 8b c7 c1 e0 04 89 45 0c 8b 45 dc 01 45 0c 8b 45 f0 03 45 f4 89 45 f8 ff 75 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

