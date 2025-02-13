rule Ransom_Win64_Protron_YAA_2147906799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Protron.YAA!MTB"
        threat_id = "2147906799"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Protron"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "4B991369-7C7C-47AA-A81E-EF6ED1F5E24C" ascii //weight: 1
        $x_10_2 = {2b c1 6b c8 23 b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 83 c1 7f b8 ?? ?? ?? ?? f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

