rule Trojan_Win64_DarkMoon_GVA_2147944804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkMoon.GVA!MTB"
        threat_id = "2147944804"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkMoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c3 48 8d 3f 48 8d 3f 48 8d 3f 2a c3 48 8d 3f 48 8d 3f 48 8d 3f 48 8d 3f 32 c3 48 8d 3f 2a c3 48 8d 3f 48 8d 3f c0 c8 fe 48 8d 3f 48 8d 3f 48 8d 3f aa 48 83 e9 01}  //weight: 2, accuracy: Low
        $x_1_2 = {ac 48 8d 3f 48 8d 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

