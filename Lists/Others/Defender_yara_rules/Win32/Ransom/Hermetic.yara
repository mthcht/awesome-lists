rule Ransom_Win32_Hermetic_DC_2147818053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hermetic.DC!MTB"
        threat_id = "2147818053"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hermetic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 13 6d 4e c6 41 8b 43 04 6a 1a 59 81 c2 39 30 00 00 89 13 23 c2 33 d2 f7 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

