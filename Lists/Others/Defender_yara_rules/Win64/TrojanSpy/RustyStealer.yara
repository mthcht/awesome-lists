rule TrojanSpy_Win64_RustyStealer_B_2147946254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/RustyStealer.B"
        threat_id = "2147946254"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 c1 ea 08 34 30 80 f2 02 41 80 f0 c4 45 0f b6 c0}  //weight: 1, accuracy: High
        $x_1_2 = {49 c1 e0 30 0f b6 d2 48 c1 e2 28 4c 09 c2 0f b6 c0 48 c1 e0 20 48 09 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

