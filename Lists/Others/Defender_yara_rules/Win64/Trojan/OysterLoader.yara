rule Trojan_Win64_OysterLoader_YAB_2147912418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OysterLoader.YAB!MTB"
        threat_id = "2147912418"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OysterLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b c8 48 03 cb 8a 44 0c 20 43 32 04 13 41 88 02 4d 03 d4}  //weight: 1, accuracy: High
        $x_1_2 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

