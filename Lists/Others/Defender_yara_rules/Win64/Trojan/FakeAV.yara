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

rule Trojan_Win64_FakeAV_SLXA_2147967355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FakeAV.SLXA!MTB"
        threat_id = "2147967355"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 44 37 ff 66 0f 6d cb 4d 89 ed 66 0f 6c ca 88 e4 9c 66 48 0f 6e c1 66 48 0f 6e c8 66 48 0f 6e d2 66 49 0f 6e dd 48 89 e1 49 89 e5 44 89 c9 48 01 f1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_FakeAV_ZHE_2147967357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FakeAV.ZHE!MTB"
        threat_id = "2147967357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FakeAV"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5a 59 5b 58 66 0f fd c2 66 0f 6c d3 66 0f 6f cb 30 44 37 ff 50 53 51 52 55}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

