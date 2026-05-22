rule Trojan_Win64_MassLogger_AMD_2147969978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MassLogger.AMD!MTB"
        threat_id = "2147969978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {49 8b c2 45 8b c4 4c 8b d2 48 8b c8 48 c1 ea ?? 48 c1 e1 ?? 48 33 c8 48 33 d1 48 c1 ea ?? 49 33 d2 48 33 d1 4e 8d 1c 12 42 8d 0c c5 ?? ?? ?? ?? 49 8b c3 48 d3 e8 41 ff c0 41 30 04 19 49 ff c1 4c 3b cf 72}  //weight: 9, accuracy: Low
        $x_1_2 = "Decryption OK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

