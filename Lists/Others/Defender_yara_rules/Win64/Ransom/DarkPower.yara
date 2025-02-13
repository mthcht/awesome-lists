rule Ransom_Win64_DarkPower_CT_2147845140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/DarkPower.CT!MTB"
        threat_id = "2147845140"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkPower"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 5c 24 60 48 23 5c 24 68 48 31 cb 48 8b 4c 24 50 48 31 d3 48 23 8c 24 90 00 00 00 48 33 4c 24 28 4d 31 f9 48 33 4c 24 30 4d 31 d9 48 31 c1 48 8b 44 24 48 4c 31 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

