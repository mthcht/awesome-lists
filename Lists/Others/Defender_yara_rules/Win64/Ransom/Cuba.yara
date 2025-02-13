rule Ransom_Win64_Cuba_FS_2147851179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Cuba.FS!MTB"
        threat_id = "2147851179"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Cuba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 08 41 b8 00 00 02 00 48 8b d3 48 8b c8 41 ff 51 70 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

