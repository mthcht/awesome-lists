rule Ransom_Win32_Flocked_YAD_2147932753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Flocked.YAD!MTB"
        threat_id = "2147932753"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Flocked"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {33 0c bb 8b 7d 0c 8b 45 fc 31 0f 8b 4c 83 08 8b c1 8b b3 38 20 00}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

