rule Trojan_Win64_Krypter_AM_2147808529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Krypter.AM!MTB"
        threat_id = "2147808529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Krypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c8 e8 ?? ?? ?? ?? 48 8b cb 41 8b c7 80 31 ?? 48 ff c1 48 83 e8 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

