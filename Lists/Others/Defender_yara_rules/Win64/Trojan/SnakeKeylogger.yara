rule Trojan_Win64_SnakeKeylogger_SPK_2147889377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SnakeKeylogger.SPK!MTB"
        threat_id = "2147889377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SnakeKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b d1 41 b9 04 00 00 00 33 c9 44 8b c7 48 8b 74 24 48 48 83 c4 30 5f 48 ff 25 ac ca 32 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

