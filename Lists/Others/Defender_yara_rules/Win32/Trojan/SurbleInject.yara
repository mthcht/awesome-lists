rule Trojan_Win32_SurbleInject_MKV_2147845591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SurbleInject.MKV!MTB"
        threat_id = "2147845591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SurbleInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 44 0f 28 86 ?? ?? ?? ?? 0f 11 44 24 ?? 0f 28 86 ?? ?? ?? ?? 0f 11 44 24 ?? 0f 28 86 ?? ?? ?? ?? 0f 11 44 24 ?? 0f 28 86 ?? ?? ?? ?? 0f 11 44 24 ?? ?? ?? 24 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = "\\ncobjapi\\Release\\cryptsp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

