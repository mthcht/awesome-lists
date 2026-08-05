rule Trojan_Win32_RemusStealer_SL_2147975254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemusStealer.SL!MTB"
        threat_id = "2147975254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 89 24 da 4e 8b 1c d8 4d 0f af dd 4c 01 ee 4f 8d 14 5a eb 53 4a c7 04 da 00 00 00 00 4e 8b 1c d8}  //weight: 1, accuracy: High
        $x_1_2 = "main.nwpryqfxbwwrd" ascii //weight: 1
        $x_1_3 = "main.ehayvkthxbtozsuk" ascii //weight: 1
        $x_1_4 = "main.affayccuimjlbdnqgw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

