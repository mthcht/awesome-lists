rule Trojan_Win64_InjectorNetT_A_2147939491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InjectorNetT.A!MTB"
        threat_id = "2147939491"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 66 8a 4d 67 88 c2 80 f2 ff 80 e2 01 41 b0 01 45 88 c1 41 80 f1 01 41 88 c2 45 20 ca 44 08 d2 80 f2 ff 80 f2 01 80 e2 ff 45 88 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

