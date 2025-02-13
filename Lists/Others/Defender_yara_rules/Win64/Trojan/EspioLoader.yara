rule Trojan_Win64_EspioLoader_A_2147852353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EspioLoader.A!MTB"
        threat_id = "2147852353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EspioLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 8b c5 f7 74 24 ?? 48 8b 45 ?? 0f be 14 02 41 33 d0 48 8b 4f ?? 4c 8b 47 ?? 49 3b c8 73 ?? 48 8d 41 ?? 48 89 47 ?? 48 8b c7 49 83 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

