rule Trojan_Win32_Shadowpad_AMMF_2147917716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shadowpad.AMMF!MTB"
        threat_id = "2147917716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shadowpad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c1 88 02 8b c1 e8 ?? ?? ?? ?? 89 45 fc 8b c1 e8 ?? ?? ?? ?? 03 45 fc e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 42 [0-5] 8b c8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

