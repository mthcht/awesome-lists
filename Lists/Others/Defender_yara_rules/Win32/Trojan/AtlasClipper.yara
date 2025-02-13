rule Trojan_Win32_AtlasClipper_SK_2147850740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AtlasClipper.SK!MTB"
        threat_id = "2147850740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AtlasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "YourMutex" ascii //weight: 2
        $x_2_2 = "ATLAS Clipper" ascii //weight: 2
        $x_2_3 = "https://t.me/atlasclipper_channel" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

