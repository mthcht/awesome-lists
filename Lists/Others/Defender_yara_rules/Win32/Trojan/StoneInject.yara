rule Trojan_Win32_StoneInject_YBM_2147969180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StoneInject.YBM!MTB"
        threat_id = "2147969180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StoneInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6a 11 ff d7 66 85 c0 7d 09 6a 7b ff d7 66 85 c0 7c 15}  //weight: 4, accuracy: High
        $x_1_2 = {68 d3 00 00 00 c7 05 ?? ?? ?? ?? d3 00 00 00 51 eb 0c 8b 15 ?? ?? ?? ?? 68 ce 00 00 00 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

