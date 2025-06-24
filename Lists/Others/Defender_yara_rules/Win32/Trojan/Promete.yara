rule Trojan_Win32_Promete_YAA_2147944449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Promete.YAA!MTB"
        threat_id = "2147944449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Promete"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d c6 80 42 75 9f 00 73 c6 80 ?? ?? ?? ?? 68 c6 80 ?? ?? ?? ?? 6c c6 80 ?? ?? ?? ?? 70 c6 80 ?? ?? ?? ?? 64 c6 80 ?? ?? ?? ?? 61 53 c6 80 48 75 9f 00 33 68}  //weight: 1, accuracy: Low
        $x_10_2 = {8a 4d fc 02 c8 30 0f 3b c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

