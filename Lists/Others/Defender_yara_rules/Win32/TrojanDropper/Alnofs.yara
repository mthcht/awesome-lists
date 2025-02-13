rule TrojanDropper_Win32_Alnofs_A_2147625919_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alnofs.A"
        threat_id = "2147625919"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alnofs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 4d 5a 90 00 03 00 00 00 28 26 00 07 00 50 00 4c 00 55 00 47 00 49 00 4e 00 53 00 02 00 50 00 30 00 08 90 6d 00 61 00 69 00 6e 00 69 00 63 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

