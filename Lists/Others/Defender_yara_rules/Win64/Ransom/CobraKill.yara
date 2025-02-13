rule Ransom_Win64_CobraKill_YAB_2147916952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/CobraKill.YAB!MTB"
        threat_id = "2147916952"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "CobraKill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 0f be 7d 00 48 63 84 24 88 00 00 00 49 31 c7 4c 89 f8 50 48 8b ac 24 a8 00 00 00 58 88 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {f7 80 14 e8 2e ad 6b f9 73 9e e9 21 43 c5 d9 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

