rule Trojan_Win64_Darkkomet_KK_2147968223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Darkkomet.KK!MTB"
        threat_id = "2147968223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Darkkomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {44 89 ca 83 e2 01 f7 da 21 ca 31 d5 8d 14 09 41 89 d3 41 83 f3 1b 84 c9 41 0f 48 d3 41 d0 e9 41 83 ea 01}  //weight: 20, accuracy: High
        $x_10_2 = {89 c2 41 69 c5 83 00 00 00 01 c2 48 89 d0 48 69 d2 39 8e e3 38 48 c1 ea 23 8d 14 d2 c1 e2 02 29 d0 41 0f b6 04 07 41 88 46 ff 49 39 ee}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

