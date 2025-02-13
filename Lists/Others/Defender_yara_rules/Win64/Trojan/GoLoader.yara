rule Trojan_Win64_GoLoader_EC_2147919988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoLoader.EC!MTB"
        threat_id = "2147919988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 ba 00 00 1a 3d eb 03 b2 a1 48 8d 04 0a e8 45 d0 fe ff b8 40 42 0f 00 e8 7b d1 fe ff 44 0f 11 bc 24 b8 01 00 00 e8 0d b4 f4 ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

