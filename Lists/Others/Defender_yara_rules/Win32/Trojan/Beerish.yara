rule Trojan_Win32_Beerish_O_2147749743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Beerish.O!dha"
        threat_id = "2147749743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Beerish"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 68 02 00 00 80 e8 ?? ?? ?? 00 83 c4 08 a3 ?? ?? ?? ?? 6a 02 68 02 00 00 80 e8 ?? ?? ?? 00 83 c4 08 a3 ?? ?? ?? ?? 6a 03 68 02 00 00 80}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 01 00 00 00 b9 02 00 00 80 e8 ?? ?? ?? 00 48 ?? ?? ?? ?? ?? ?? ba 02 00 00 00 b9 02 00 00 80 e8 ?? ?? ?? 00 48 ?? ?? ?? ?? ?? ?? ba 03 00 00 00 b9 02 00 00 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

