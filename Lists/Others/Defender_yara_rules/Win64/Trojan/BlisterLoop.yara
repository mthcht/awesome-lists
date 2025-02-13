rule Trojan_Win64_BlisterLoop_A_2147833253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BlisterLoop.A"
        threat_id = "2147833253"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BlisterLoop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 ff ff ff 7f 41 bc 01 00 00 00 89 45 40 f0 ff 4d 40 49 2b c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

