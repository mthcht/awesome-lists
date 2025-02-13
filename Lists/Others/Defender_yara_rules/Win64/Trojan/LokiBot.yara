rule Trojan_Win64_LokiBot_RDH_2147845957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LokiBot.RDH!MTB"
        threat_id = "2147845957"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LokiBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c9 48 8d 40 01 33 ca 69 d1 fb e3 ed 25 0f b6 08 84 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

