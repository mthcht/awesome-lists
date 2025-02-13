rule Trojan_Win64_Gulpix_RPX_2147888466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gulpix.RPX!MTB"
        threat_id = "2147888466"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gulpix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 33 c4 48 89 84 24 20 05 00 00 45 33 ed 4d 8b e1 33 c9 49 8b dd 41 8d 55 0c 45 8d 4d 40 41 b8 00 30 00 00 41 c6 43 c8 48 41 c6 43 c9 b8 41 88 5b ca 41 88 5b cb 41 88 5b cc 41 88 5b cd 41 88 5b ce 41 88 5b cf 41 88 5b d0 41 88 5b d1 41 c6 43 d2 ff 41 c6 43 d3 e0 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

