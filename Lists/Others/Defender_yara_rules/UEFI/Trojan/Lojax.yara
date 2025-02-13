rule Trojan_UEFI_Lojax_H_2147750109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:UEFI/Lojax.H!UEFI"
        threat_id = "2147750109"
        type = "Trojan"
        platform = "UEFI: "
        family = "Lojax"
        severity = "Critical"
        info = "UEFI: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 b9 03 00 00 00 00 00 00 80 [0-31] ff ?? 08 [0-47] ff ?? 28 [0-31] ff ?? 10}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c1 0f b6 00 83 f8 61 0f [0-37] 0f b6 40 01 85 c0 [0-38] 0f b6 40 02 83 f8 75}  //weight: 1, accuracy: Low
        $x_1_3 = {45 33 c9 45 33 c0 33 d2 48 8b ?? ?? ?? 48 8b ?? ?? ?? 48 8b ?? ?? 48 8b ?? ?? ?? ?? ?? ff 90 08 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 9b 2d 83 d5 d8 5f 42 bd 52 5c 5a fb 2c 85 dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

