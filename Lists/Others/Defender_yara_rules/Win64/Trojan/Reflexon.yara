rule Trojan_Win64_Reflexon_LK_2147847993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Reflexon.LK!MTB"
        threat_id = "2147847993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Reflexon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/rev.aes" wide //weight: 1
        $x_1_2 = {50 72 6f 6a 65 63 74 [0-4] 5f 42 79 70 61 73 73 48 6f 6f 6b 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 6a 65 63 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

