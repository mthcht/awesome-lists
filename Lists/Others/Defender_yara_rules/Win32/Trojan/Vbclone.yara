rule Trojan_Win32_Vbclone_RPX_2147908371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbclone.RPX!MTB"
        threat_id = "2147908371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbclone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 f8 64 35 00 00 00 00 00 ff cc 31 00 04 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

