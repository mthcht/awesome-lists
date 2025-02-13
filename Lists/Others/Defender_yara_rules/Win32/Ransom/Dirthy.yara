rule Ransom_Win32_Dirthy_YAB_2147921112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dirthy.YAB!MTB"
        threat_id = "2147921112"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dirthy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d e4 89 4d d8 8b 55 d8 0f be 02 35 aa 00 00 00 8b 4d d8 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

