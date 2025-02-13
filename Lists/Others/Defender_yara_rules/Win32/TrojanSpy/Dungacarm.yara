rule TrojanSpy_Win32_Dungacarm_A_2147683765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dungacarm.A"
        threat_id = "2147683765"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dungacarm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {62 00 6f 00 74 00 5f 00 [0-4] 5c 00 63 00 61 00 63 00 61 00 5f 00 62 00 6f 00 74 00 5f 00}  //weight: 10, accuracy: Low
        $x_5_2 = "caramandunga" wide //weight: 5
        $x_5_3 = "cakitarlz.us/1/contador.php" wide //weight: 5
        $x_5_4 = "esperamerlz.us/1/ab.php" wide //weight: 5
        $x_5_5 = "veydileok.co.uk/1/ab.php" wide //weight: 5
        $x_5_6 = "\\upgrates.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

