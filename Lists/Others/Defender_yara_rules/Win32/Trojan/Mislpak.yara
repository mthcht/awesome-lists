rule Trojan_Win32_Mislpak_A_2147935068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mislpak.A"
        threat_id = "2147935068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mislpak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "108"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 100, accuracy: High
        $x_5_2 = {06 20 00 01 00 00 6f ?? ?? ?? 0a 06 72 01 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 72 5b 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 0a 00 00 0a 0c}  //weight: 5, accuracy: Low
        $x_1_3 = "Costura" ascii //weight: 1
        $x_1_4 = "protobuf-net" ascii //weight: 1
        $x_1_5 = {0d 57 72 69 74 65 20 00 11 50 72 6f 63 65 73 73 20 00 0d 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {3c 50 72 69 76 61 74 65 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 44 65 74 61 69 6c 73 3e 7b 32 32 37 36 39 31 34 35 2d 30 46 43 43 2d 34 39 35 33 2d 38 42 33 41 2d 32 46 30 42 33 34 32 42 45 43 43 42 7d 00}  //weight: 1, accuracy: High
        $x_1_7 = "0CAAB77D26DA3539E24CAF9E88C59C63DDF3423FE0A713B5DD42B656D0343B0D" ascii //weight: 1
        $x_1_8 = "10714BD818A457DFD807368AD3762BBA6B7E2E7169282A8576B45E12419C15C5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

