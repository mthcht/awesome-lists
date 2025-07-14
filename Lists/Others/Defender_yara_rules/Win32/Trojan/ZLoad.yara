rule Trojan_Win32_ZLoad_AHB_2147946295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZLoad.AHB!MTB"
        threat_id = "2147946295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 ca 80 c2 ?? 32 54 0c 04 80 c2 ?? 88 54 0c 04 41 83 f9 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

