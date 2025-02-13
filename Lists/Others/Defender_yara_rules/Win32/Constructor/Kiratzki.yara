rule Constructor_Win32_Kiratzki_A_2147647724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Kiratzki.A"
        threat_id = "2147647724"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kiratzki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RatExtractor" ascii //weight: 2
        $x_2_2 = "RatCenter" ascii //weight: 2
        $x_2_3 = "RatDecryptor" ascii //weight: 2
        $x_2_4 = "FileConnector.exe" ascii //weight: 2
        $x_2_5 = "therat.h15.ru" ascii //weight: 2
        $x_1_6 = "ALL ACTIVITIES ON THIS SYSTEM ARE MONITORED" ascii //weight: 1
        $x_1_7 = "HandyCat" ascii //weight: 1
        $x_1_8 = "c:\\rat.dat" ascii //weight: 1
        $x_1_9 = "The Rat!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

