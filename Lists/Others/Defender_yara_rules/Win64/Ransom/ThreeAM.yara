rule Ransom_Win64_ThreeAM_B_2147935781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ThreeAM.B"
        threat_id = "2147935781"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ThreeAM"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 f1 48 3d 01 00 50 00 0f 83}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 f1 b2 31 66 41 b8 30 31 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

