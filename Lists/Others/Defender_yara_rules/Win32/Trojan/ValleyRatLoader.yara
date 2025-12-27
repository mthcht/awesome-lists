rule Trojan_Win32_ValleyRatLoader_CI_2147955315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValleyRatLoader.CI!MTB"
        threat_id = "2147955315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValleyRatLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c2 0f b6 c0 0f b6 44 04 ?? 30 04 0e 46 3b f7 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

