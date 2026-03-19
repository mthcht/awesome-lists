rule Trojan_Win64_BlackBeard_DA_2147965147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlackBeard.DA!MTB"
        threat_id = "2147965147"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackBeard"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "jfdghkjfdgklhjdfhgsfd09g9045jlkdfjlkgedfg5949045dfjgdflgljkdfgdf" ascii //weight: 10
        $x_1_2 = {5c 00 70 00 68 00 6f 00 6e 00 69 00 78 00 [0-6] 5c 00 70 00 68 00 6f 00 65 00 6e 00 69 00 78 00 [0-6] 5c 00 78 00 36 00 34 00 5c 00 [0-15] 5c 00 70 00 68 00 6f 00 65 00 6e 00 69 00 78 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 70 68 6f 6e 69 78 [0-6] 5c 70 68 6f 65 6e 69 78 [0-6] 5c 78 36 34 5c [0-15] 5c 70 68 6f 65 6e 69 78 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = "encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

