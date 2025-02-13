rule PWS_Win32_Barus_A_2147659827_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Barus.A"
        threat_id = "2147659827"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Barus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 89 e7 ac 88 c7 8a 27 47 c0 ec 04 28 e0 73 f6 8a 47 ff 24 0f 3c 0c 75 03 5a f7 d2}  //weight: 10, accuracy: High
        $x_1_2 = "--7d015813802c4" ascii //weight: 1
        $x_1_3 = "money.yandex.ru" ascii //weight: 1
        $x_1_4 = "raiffeisen.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

