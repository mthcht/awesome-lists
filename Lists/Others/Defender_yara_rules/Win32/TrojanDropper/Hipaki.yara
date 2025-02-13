rule TrojanDropper_Win32_Hipaki_A_2147629887_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Hipaki.A"
        threat_id = "2147629887"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Hipaki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 2f 45 80 37 1b 80 37 45 f6 17 47 e2 f2}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 00 00 80 86 db 68 ?? ?? ?? ?? 86 db 68 ?? ?? ?? ?? 86 db 50 86 db c3 86 db a3 ?? ?? ?? ?? 86 db 83 f8 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

