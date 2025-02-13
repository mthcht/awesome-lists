rule Trojan_Win32_Nimnul_SA_2147835597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nimnul.SA!MTB"
        threat_id = "2147835597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nimnul"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {81 04 88 d5 fb da 4f 33 15 ?? ?? ?? ?? 33 fc 8b 7d f0 89 1d ?? ?? ?? ?? 8b 75 f8 83 c1 01 81 f9 6a 07 00 00 0f 82 d6 ff ff ff}  //weight: 3, accuracy: Low
        $x_2_2 = "Xqdjztb.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

