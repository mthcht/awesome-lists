rule Ransom_Win64_BlackBasta_MP_2147835199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackBasta.MP!MTB"
        threat_id = "2147835199"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 88 4b 70 c1 e8 08 88 43 71 8b c1 c1 e8 10 88 43 72 c1 e9 18 88 4b 73 8b 4c 24 54 8b c1 88 4b 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

