rule Trojan_Win32_IRCBor_LK_2147845455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBor.LK!MTB"
        threat_id = "2147845455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe c1 8a 04 19 8a 14 18 88 04 1a 88 14 18 30 07 47 4d 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

