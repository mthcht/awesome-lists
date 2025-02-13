rule Trojan_Win32_Zload_E_2147756447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zload.E!MTB"
        threat_id = "2147756447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6c 24 10 8b 55 00 83 44 24 10 04 81 c2 ?? ?? ?? ?? 89 55 00 83 6c 24 14 01 75 a7}  //weight: 1, accuracy: Low
        $x_1_2 = "bread\\excite\\Storybone.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

