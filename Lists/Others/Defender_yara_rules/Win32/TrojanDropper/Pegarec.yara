rule TrojanDropper_Win32_Pegarec_A_2147730997_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pegarec.A"
        threat_id = "2147730997"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pegarec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 20 00 2d 00 6f 00 2b 00 20 00 2d 00 72 00 20 00 2d 00 69 00 6e 00 75 00 6c 00 20 00 [0-32] 2e 00 6a 00 70 00 67 00 20 00 [0-32] 2e 00 65 00 78 00 65 00 20 00 26 00 20 00 01 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

