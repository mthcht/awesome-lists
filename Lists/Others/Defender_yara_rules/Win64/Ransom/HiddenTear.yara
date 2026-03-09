rule Ransom_Win64_HiddenTear_NR_2147964344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/HiddenTear.NR!MTB"
        threat_id = "2147964344"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 8c 24 88 00 00 00 ba 10 00 00 00 89 c5 0f b6 f0 0f b6 fc c1 e8 18 c1 ed 10 89 74 24 30 41 89 c1 44 0f b6 c5 89 7c 24 28 bd 00 02 00 00 44 89 44 24 20}  //weight: 2, accuracy: High
        $x_1_2 = {41 89 c4 89 c2 e9 85 00 00 00 80 fa 18 0f 85 81 00 00 00 48 8b 7c 24 60 49 8d 74 0e 02 0f b6 cb 41 bf 01 00 00 00 f3 a4 48 8b 4c 24 60}  //weight: 1, accuracy: High
        $x_1_3 = "Connected to C&C server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

