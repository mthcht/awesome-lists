rule Trojan_Win32_Preflayer_A_2147680004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Preflayer.A"
        threat_id = "2147680004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Preflayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2a 20 59 4f 55 52 20 42 52 4f 57 53 45 52 20 48 4f 4d 45 50 41 47 45 [0-32] 57 49 4c 4c 20 43 48 41 4e 47 45 20 57 49 54 48 [0-21] 49 46 20 59 4f 55 20 41 43 43 45 50 54 20 54 48 49 53 2c 20 50 4c 45 41 53 45 20 43 4f 4e 54 49 4e 55 45 2e}  //weight: 5, accuracy: Low
        $x_5_2 = "ADOBE SHALL NOT BE LIABLE TO YOU OR ANY OTHER PARTY" ascii //weight: 5
        $x_5_3 = {46 00 69 00 72 00 65 00 66 00 6f 00 78 00 ?? ?? ?? ?? ?? ?? 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 ?? ?? ?? ?? ?? ?? 43 00 68 00 72 00 6f 00 6d 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 59 00 61 00 6e 00 64 00 65 00 78 00}  //weight: 5, accuracy: Low
        $x_5_4 = {27 69 20 79 fc 6b 6c 65 6d 65 6b 20 69 e7 69 6e 20 6c fc 74 66 65 6e 20 27 69 6c 65 72 69 27 20 62 75 74 6f 6e 75 6e 61}  //weight: 5, accuracy: High
        $x_2_5 = "FlashPlayer11.exe" ascii //weight: 2
        $x_2_6 = "FlashPlayer11.exe" wide //weight: 2
        $x_1_7 = "heydex.com" ascii //weight: 1
        $x_1_8 = "anasayfada.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

