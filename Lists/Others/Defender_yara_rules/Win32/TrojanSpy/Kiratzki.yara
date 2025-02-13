rule TrojanSpy_Win32_Kiratzki_A_2147647723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Kiratzki.A"
        threat_id = "2147647723"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Kiratzki"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mybestbox@mail.ru" ascii //weight: 2
        $x_2_2 = "socketme.exe" wide //weight: 2
        $x_2_3 = "therat.h15.ru" ascii //weight: 2
        $x_2_4 = "shutdown.exe" ascii //weight: 2
        $x_2_5 = "RatLogPart-12345" ascii //weight: 2
        $x_1_6 = "CURRENT WINDOW TEXT:" ascii //weight: 1
        $x_1_7 = "WRITE IN FILE:" ascii //weight: 1
        $x_1_8 = "TO: The_Owner_of_The_Rat!" ascii //weight: 1
        $x_1_9 = "SUBJECT: user_one" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

