rule Trojan_Win32_AresLdrShell_LK_2147845763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AresLdrShell.LK!MTB"
        threat_id = "2147845763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AresLdrShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 55 ?? ff 54}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 30 00 00 55 ff ?? ?? ff 54}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 42 04 03 47 08 8b 4a fc 03 cb 8a 04 30 88 04 31 46 3b 32 72 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

