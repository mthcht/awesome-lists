rule Virus_Win64_Sirefef_B_2147657891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Sirefef.B"
        threat_id = "2147657891"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 bc fd ff ff 3b c7 7c 1b 48 8b 84 24 e0 00 00 00 66 39 78 06 74 0d 48 83 c0 0c 45 33 c0 33 d2 33 c9 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win64_Sirefef_B_2147657891_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win64/Sirefef.B"
        threat_id = "2147657891"
        type = "Virus"
        platform = "Win64: Windows 64-bit platform"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 bc fd ff ff 3b c7 7c 1b 48 8b 84 24 e0 00 00 00 66 39 78 06 74 0d 48 83 c0 0c 45 33 c0 33 d2 33 c9 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

