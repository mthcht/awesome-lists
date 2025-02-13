rule Trojan_Win64_LummaStealz_AT_2147920421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaStealz.AT!MTB"
        threat_id = "2147920421"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c 47 c7 ea 3f 9c bd 67 ab 54 4f e5 6e 60 c8 9d 27 0f 41 1c ac c6 50 69 9f 75 17 93 c0 90 eb 5b 2b ba a5 e5 17 f5 0e 37 47 28 07 8e ec 41 b6 bb fe 27 69 bd 6a a6 f7 04 e1 b8 e9 b7 7c 22 8f d2 0e 38 50 dc 19 95 91 da 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

