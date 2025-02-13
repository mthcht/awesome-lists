rule Trojan_Win32_NsInject_CT_2147744724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NsInject.CT!MTB"
        threat_id = "2147744724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NsInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 8d a4 24 00 00 00 00 8a 14 8d ?? ?? ?? ?? 80 c2 ?? 88 14 01 83 c1 01 81 f9 ?? ?? 00 00 7c e8 8d 0c 24 51 05 ?? ?? 00 00 ff d0 b8 ?? ?? 00 00 83 c4 1c c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 04 33 c0 eb ?? 8d a4 24 00 00 00 00 [0-16] 8a 14 85 ?? ?? ?? ?? 80 c2 ?? 88 14 08 83 c0 01 3d ?? ?? 00 00 7c ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

