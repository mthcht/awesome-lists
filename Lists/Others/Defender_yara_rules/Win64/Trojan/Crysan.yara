rule Trojan_Win64_Crysan_ACR_2147954541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Crysan.ACR!MTB"
        threat_id = "2147954541"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 44 24 70 48 89 44 24 50 44 89 64 24 48 44 89 64 24 40 44 89 64 24 38 44 89 64 24 30 44 89 64 24 28 44 89 64 24 20 41 b9 20 02 00 00 41 b8 20 00 00 00 b2 02 48 8d 4d 1c}  //weight: 2, accuracy: High
        $x_1_2 = {48 83 7d a8 0f 48 0f 47 55 90 48 8d 44 24 78 48 89 44 24 48 48 8d 45 b0 48 89 44 24 40 48 89 5c 24 38 48 89 5c 24 30 c7 44 24 28 08 00 00 08 89 5c 24 20 45 33 c9 45 33 c0 33 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

