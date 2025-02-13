rule Trojan_Win32_Godzilia_A_2147717257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Godzilia.A"
        threat_id = "2147717257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Godzilia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff 06 02 00 00 ?? ?? ?? ?? ff ff 00 a4 00 00 ?? ?? ?? ?? ff ff 52 53 41 31 ?? ?? ?? ?? ff ff 00 08 00 00 ?? ?? ?? ?? ff ff 01 00 01 00 ?? ?? ?? ?? ff ff bf 77 25 70 ?? ?? ?? ?? ff ff 30 d2 df ad ?? ?? ?? ?? ff ff 2a 81 bf 7a ?? ?? ?? ?? ff ff 26 4c bb b8 ?? ?? ?? ?? ff ff 3d 1a 9c 7f}  //weight: 1, accuracy: Low
        $x_1_2 = {47 4f 44 5a ?? ?? ?? 49 4c 69 7a}  //weight: 1, accuracy: Low
        $x_1_3 = {cf 11 bb 82 ?? ?? ?? 00 aa 00 bd ?? ?? ?? ?? ce 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

