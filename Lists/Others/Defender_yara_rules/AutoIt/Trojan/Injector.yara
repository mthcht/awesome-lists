rule Trojan_AutoIt_Injector_F_2147716561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AutoIt/Injector.F!bit"
        threat_id = "2147716561"
        type = "Trojan"
        platform = "AutoIt: AutoIT scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {23 00 41 00 75 00 74 00 6f 00 49 00 74 00 33 00 57 00 72 00 61 00 70 00 70 00 65 00 72 00 5f 00 49 00 63 00 6f 00 6e 00 3d 00 45 00 3a 00 5c 00 42 00 61 00 6e 00 6b 00 73 00 5c 00 42 00 6f 00 74 00 6f 00 65 00 73 00 20 00 2b 00 [0-128] 2e 00 69 00 63 00 6f 00}  //weight: 5, accuracy: Low
        $x_1_2 = "123x34x2ef15" wide //weight: 1
        $x_1_3 = "5544xx2223334xx" wide //weight: 1
        $x_1_4 = "JP1358JYDP4VGUGDA" wide //weight: 1
        $x_1_5 = "IOFAHEBQ7TKGVGHPE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

