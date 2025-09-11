rule Trojan_Win32_ShellCodeLoader_KK_2147951992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellCodeLoader.KK!MTB"
        threat_id = "2147951992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellCodeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {20 20 20 20 20 20 20 20 6a b1 04 00 00 10 00 00 00 88 02 00 00 04}  //weight: 20, accuracy: High
        $x_10_2 = {40 00 00 c0 20 20 20 20 20 20 20 20 ec 40 00 00 00 c0 09 00 00 38 00 00 00 3a 04}  //weight: 10, accuracy: High
        $x_5_3 = {40 2e 74 68 65 6d 69 64 61 00 ?? ?? 00 00 ?? 0f 00 00 ?? ?? 00 00 ?? 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

