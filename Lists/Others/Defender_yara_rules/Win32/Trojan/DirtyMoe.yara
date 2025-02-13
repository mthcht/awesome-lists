rule Trojan_Win32_DirtyMoe_A_2147891225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DirtyMoe.A!MTB"
        threat_id = "2147891225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DirtyMoe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 01 99 b9 ?? ?? ?? ?? f7 f9 81 c2 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 8a 08 32 ca 8b 55 ?? 03 55 ?? 88 0a 8b 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

