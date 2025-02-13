rule Trojan_Win32_Xploder_GNE_2147925057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xploder.GNE!MTB"
        threat_id = "2147925057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xploder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1b f2 30 66 ?? 4a 5d 20 23}  //weight: 5, accuracy: Low
        $x_5_2 = {10 1e 95 0d ?? ?? ?? ?? e4 ?? 51 d0 55 ?? 30 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

