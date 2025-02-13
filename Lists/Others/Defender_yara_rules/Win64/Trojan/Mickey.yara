rule Trojan_Win64_Mickey_CBVV_2147852322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mickey.CBVV!MTB"
        threat_id = "2147852322"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mickey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 0b 44 c6 45 0c 41 c6 45 0d 56 c6 45 0e 58 c6 45 0f 5d c6 45 10 47 c6 45 11 5c c6 45 12 51 c6 45 13 46 c6 45 14 4b c6 45 15 46 c6 45 16 41 c6 45 17 5a c6 45 18 5a c6 45 19 51 c6 45 1a 46 c6 45 1b 34}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 44 15 0b 8b 4d 07 32 c8 88 4c 15 0b 48 ff c2 48 83 fa ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

