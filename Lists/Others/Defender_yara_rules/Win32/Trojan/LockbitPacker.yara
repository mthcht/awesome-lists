rule Trojan_Win32_LockbitPacker_2147820128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LockbitPacker!MTB"
        threat_id = "2147820128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LockbitPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55 0c 73 1c 0f b6 05 ?? ?? ?? ?? 8b 4d 08 03 4d fc 0f b6 11 2b d0 8b 45 08 03 45 fc 88 10 eb d3 b8 ?? ?? ?? ?? 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

