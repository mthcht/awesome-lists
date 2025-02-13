rule TrojanSpy_Win32_Wordapas_A_2147628134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wordapas.A"
        threat_id = "2147628134"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wordapas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 74 50 6a 03 8d 85 ?? ff ff ff 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 83 c4 0c 85 c0 74 36}  //weight: 2, accuracy: Low
        $x_2_2 = {68 04 20 00 00 8d 85 ?? ?? ff ff 50 57 ff 15 ?? ?? 40 00 39 9d ?? ?? ff ff 89 9d ?? ?? ff ff 76 56}  //weight: 2, accuracy: Low
        $x_2_3 = {5b 54 5d 00 33 c0 8d bd ?? ?? 00 00 66 ab aa 66 c7 85 ?? ?? 00 00 71 00 33 c0 8d bd ?? ?? 00 00 ab aa 66 c7 85 ?? ?? 00 00 77 00 33 c0 8d bd ?? ?? 00 00 ab aa 66 c7 85 ?? ?? 00 00 65 00}  //weight: 2, accuracy: Low
        $x_2_4 = {e9 99 00 00 00 8d 85 ?? ?? ff ff 50 ff d6 83 f8 0d 0f 8e 9b 00 00 00 8d 85 ?? ?? ff ff 50 bf ?? ?? 40 00 ff d6 8d b4 ?? ?? ff ff ff 6a 0b 59 33 c0 f3 a6 75 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

