rule Trojan_Win64_FakeAV_AFA_2147933379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FakeAV.AFA!MTB"
        threat_id = "2147933379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 54 48 89 c8 49 89 d4 41 b9 04 00 00 00 55 31 c9 57 56 4c 89 c6 53 48 83 c6 04 48 83 ec 30 41 8b 28 41 b8 00 30 00 00 48 89 ea ff d0 48 89 e9 4c 8d 4c 24 2c 41 b8 20 00 00 00 48 89 c7 48 89 c3 48 89 ea f3 a4 48 89 c1 41 ff d4 31 c9 ff d3 01 00 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

