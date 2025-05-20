rule Trojan_Win64_PassTamper_A_2147941740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PassTamper.A"
        threat_id = "2147941740"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PassTamper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 ff ba 00 01 00 00 41 8b ff e8 ?? ?? ?? ?? 48 85 c0 74 ?? 0f 1f 40 00 0f 1f 84 00 00 00 00 00 4c 8b c6 48 8d 8c 24 90 00 00 00 ba 00 01 00 00 48 ff c7}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 00 73 00 79 00 73 00 00 00 00 00 4e 00 76 00 4b 00 65 00 72 00 62 00 65 00 6c 00 00 00 00 ?? 00 00 00 00 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 2d 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

