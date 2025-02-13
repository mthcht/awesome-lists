rule Trojan_Win64_AresLdrCrypt_LKC_2147845847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AresLdrCrypt.LKC!MTB"
        threat_id = "2147845847"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AresLdrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8a 04 10 48 8b 44 24 ?? 44 32 04 08 45 88 04 09 48 ff c1 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

