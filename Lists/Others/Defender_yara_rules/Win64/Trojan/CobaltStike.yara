rule Trojan_Win64_CobaltStike_YBD_2147931723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStike.YBD!MTB"
        threat_id = "2147931723"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {01 03 b8 01 00 00 00 2b c1 01 43 18 8b 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 83 c0 fa 03 c1 48 63 8b ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 0f b6 43}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

