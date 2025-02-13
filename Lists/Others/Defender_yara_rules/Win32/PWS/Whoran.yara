rule PWS_Win32_Whoran_A_2147583265_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Whoran.A"
        threat_id = "2147583265"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Whoran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {83 c9 ff f2 ae f7 d1 49 85 c9 7e 21 8a 4c 14 ?? 8d 7c 24 ?? 80 f1 ?? 33 c0 88 8c 14 ?? 01 00 00 83 c9 ff 42 f2 ae}  //weight: 8, accuracy: Low
        $x_8_2 = "{TK}zzmf" ascii //weight: 8
        $x_2_3 = "Content-Type: application/x-www-form-urlencoded" ascii //weight: 2
        $x_1_4 = "MSDN SurfBear" ascii //weight: 1
        $x_1_5 = "ravmon.exe" ascii //weight: 1
        $x_1_6 = "symantec.exe" ascii //weight: 1
        $x_1_7 = "kav32.exe" ascii //weight: 1
        $x_1_8 = "&url=" ascii //weight: 1
        $x_2_9 = "&pass=" ascii //weight: 2
        $x_1_10 = "&user=" ascii //weight: 1
        $x_1_11 = "&pcname=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

