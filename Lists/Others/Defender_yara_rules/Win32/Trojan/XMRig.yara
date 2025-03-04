rule Trojan_Win32_XMRig_B_2147903173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/XMRig.B!MTB"
        threat_id = "2147903173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "XMRig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 f4 8b 45 ?? 31 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

