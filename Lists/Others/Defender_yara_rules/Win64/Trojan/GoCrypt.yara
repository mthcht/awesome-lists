rule Trojan_Win64_GoCrypt_C_2147976519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.C!MTB"
        threat_id = "2147976519"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 34 03 31 ce 4c 8d 04 9b 41 31 f0 44 88 04 18 48 ff c3 [0-1] 48 39 da 7f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

