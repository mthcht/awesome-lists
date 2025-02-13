rule Trojan_Win32_Wastker_WR_2147758336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wastker.WR!MTB"
        threat_id = "2147758336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wastker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%c%c%c%c%c%c%c%c%cMS-%d-server" ascii //weight: 1
        $x_1_2 = {8b c2 8d 0c 3a 83 e0 03 42 8a 80 ?? ?? ?? ?? 32 04 0e 88 01 3b d3 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {68 0e 27 00 00 ff d6 85 db 74 ?? ff ?? 33 db eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

