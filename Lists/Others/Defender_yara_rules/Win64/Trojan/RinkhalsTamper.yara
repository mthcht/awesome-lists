rule Trojan_Win64_RinkhalsTamper_A_2147951412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RinkhalsTamper.A"
        threat_id = "2147951412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RinkhalsTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 83 c1 01 0f be d0 41 0f b6 41 ff 44 31 da 44 69 da 93 01 00 01 84 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

