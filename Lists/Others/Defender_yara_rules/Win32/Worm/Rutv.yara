rule Worm_Win32_Rutv_A_2147625210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rutv.A"
        threat_id = "2147625210"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rutv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "autorun.inf" ascii //weight: 10
        $x_10_2 = "SpreadToNetwork" ascii //weight: 10
        $x_10_3 = "NetShareAdd" ascii //weight: 10
        $x_10_4 = "NetShareEnum" ascii //weight: 10
        $x_1_5 = "http://pornoslon.ru/index.php?board=" ascii //weight: 1
        $x_1_6 = "http://odnoklassniki.ru/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

