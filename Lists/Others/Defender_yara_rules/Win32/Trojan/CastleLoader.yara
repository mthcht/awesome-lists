rule Trojan_Win32_CastleLoader_MK_2147966722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CastleLoader.MK!MTB"
        threat_id = "2147966722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CastleLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {66 33 44 0c ?? 66 89 84 0c ?? ?? ?? ?? 8b c2 83 e0 ?? 0f b6 80 ?? ?? ?? ?? 66 33 44 0c ?? 66 89 84 0c ?? ?? ?? ?? 8d 42 ?? 83 e0 ?? 0f b6 80 ?? ?? ?? ?? 66 33 44 0c}  //weight: 20, accuracy: Low
        $x_10_2 = "-ExecutionPolicy Bypass -NoProfile -EncodedCommand \"%s\"" ascii //weight: 10
        $x_5_3 = "-ExecutionPolicy Bypass -NoProfile -Command \"%s\"" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

