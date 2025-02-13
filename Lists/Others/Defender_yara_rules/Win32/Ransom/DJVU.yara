rule Ransom_Win32_DJVU_KD_2147851450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DJVU.KD!MTB"
        threat_id = "2147851450"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DJVU"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 c1 e8 05 03 44 24 20 03 d5 33 c2 03 cf 33 c1 2b f0}  //weight: 1, accuracy: High
        $x_1_2 = {33 cb 31 4c 24 10 8b 44 24 10 29 44 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

