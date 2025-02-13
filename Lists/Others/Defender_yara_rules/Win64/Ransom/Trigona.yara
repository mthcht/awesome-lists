rule Ransom_Win64_Trigona_YAA_2147904059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Trigona.YAA!MTB"
        threat_id = "2147904059"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Trigona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 45 30 48 2b 45 38 48 89 45 38 48 0f b6 45 38 88 45 2f 48 0f b6 45 2f 30 03 83 ee 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

