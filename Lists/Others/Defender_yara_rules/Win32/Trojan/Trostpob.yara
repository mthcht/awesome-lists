rule Trojan_Win32_Trostpob_A_2147678442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trostpob.A"
        threat_id = "2147678442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trostpob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "klworgsuw" ascii //weight: 1
        $x_1_2 = "siueu2dowg" ascii //weight: 1
        $x_1_3 = "adowhg.php" ascii //weight: 1
        $x_1_4 = "shoheg.php" ascii //weight: 1
        $x_1_5 = "gheowt.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

