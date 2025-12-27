rule Trojan_Win32_RBot_AHB_2147946220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RBot.AHB!MTB"
        threat_id = "2147946220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d bd fb f9 ff ff f3 ab aa be ?? ?? ?? ?? 8d bd fc fe ff ff a5 a5 66 a5 a4 6a 3e 59 33 c0 8d bd 07 ff ff ff f3 ab aa 68 04 01 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = "IAMNOTHING" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

