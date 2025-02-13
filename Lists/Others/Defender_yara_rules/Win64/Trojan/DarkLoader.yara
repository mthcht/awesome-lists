rule Trojan_Win64_DarkLoader_A_2147895763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkLoader.A!MTB"
        threat_id = "2147895763"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 4c dc 60 48 8d 95 e0 ?? 00 00 4c 8b c7 ff 15 ?? ?? 00 00 85 c0 0f 88 ?? ?? ?? ?? 48 83 c7 06 48 ff c3 48 83}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

