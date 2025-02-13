rule Trojan_Win32_Black_SIB_2147794067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Black.SIB!MTB"
        threat_id = "2147794067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Black"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 0f b7 f7 59 5f 81 c7 ?? ?? ?? ?? [0-16] 33 db [0-16] ff 34 3b [0-16] 58 81 c0 ?? ?? ?? ?? [0-16] 81 f0 ?? ?? ?? ?? [0-16] 81 f0 ?? ?? ?? ?? 50 [0-16] 8f 04 1f [0-16] 83 eb ?? [0-16] 81 fb ?? ?? ?? ?? [0-16] ff 34 3b [0-16] 58 81 c0 06 [0-16] 81 f0 08 [0-16] 81 f0 ?? ?? ?? ?? 50 [0-16] 8f 04 1f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

