rule Trojan_Win32_TrickGate_A_2147898875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickGate.A!MTB"
        threat_id = "2147898875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 c8 0f b6 4d ?? 31 c8 88 c2 8b 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

