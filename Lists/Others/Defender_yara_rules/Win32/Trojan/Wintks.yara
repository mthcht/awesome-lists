rule Trojan_Win32_Wintks_A_2147627887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wintks.A"
        threat_id = "2147627887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wintks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 0e 8a 0c 28 80 f1 08 88 0c 28 40 3b c3 72 f2 68 ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? be 80 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 0a 68 00 01 00 00 50 e8 ?? ?? 00 00 8d 7c 24 10 83 c9 ff 33 c0 f2 ae f7 d1 49 8b f1 83 fe 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

