rule Ransom_Win64_Sauron_YAE_2147957045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sauron.YAE!MTB"
        threat_id = "2147957045"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sauron"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {42 0f b6 4c 05 b8 b8 bf bf 8c 82 83 f1 18 8d 0c cd 48 f8 ff ff f7 e9 03 d1 c1 fa 07 8b c2 c1 e8 1f 03 d0 69 c2 fb 00 00 00 2b c8 b8 bf bf 8c 82 81 c1 fb 00 00 00 f7 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

