rule Trojan_Win64_Loader_EC_2147903537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Loader.EC!MTB"
        threat_id = "2147903537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Loader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 8b cc 8a 45 c0 30 44 0d c1 48 ff c1 48 83 f9 14 72 f0 44 88 65 d5 0f 57 c0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

