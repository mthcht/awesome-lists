rule Trojan_Win32_Conti_GA_2147774354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conti.GA!MTB"
        threat_id = "2147774354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 0d 00 ff ff ff 40 0f b6 80 ?? ?? ?? ?? 33 ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 88 0a 28 00 03 c2 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Conti_GA_2147774354_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Conti.GA!MTB"
        threat_id = "2147774354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 45 d4 0f be 08 8b 15 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f b6 92 ?? ?? ?? ?? 03 c2 25 ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 33 c8 8b 15 ?? ?? ?? ?? 03 55 d4 88 0a e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

