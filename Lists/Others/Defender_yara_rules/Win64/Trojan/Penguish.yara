rule Trojan_Win64_Penguish_VGZ_2147966887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Penguish.VGZ!MTB"
        threat_id = "2147966887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Penguish"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c3 83 e3 0f 0f b6 9b ?? ?? ?? ?? 30 1c 02 83 c0 01 39 c1 75 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

