rule Trojan_Win32_SePanda_A_2147895860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SePanda.A!MTB"
        threat_id = "2147895860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SePanda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 8d 44 24 20 68 ?? ?? 40 00 50 ff ?? 8a 44 24 5c 83 c4 0c 84 c0 8d 74 24 50 ?? ?? 8d 4c 24 1c 51 56 ff ?? 85 c0 ?? ?? 6a 00 56 e8 ?? ?? 00 00 83 c4 08 40 8b f0 80 3e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

