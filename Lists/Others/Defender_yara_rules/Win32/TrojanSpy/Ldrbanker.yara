rule TrojanSpy_Win32_Ldrbanker_A_2147735235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ldrbanker.A"
        threat_id = "2147735235"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldrbanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\clientpc\\cliente." wide //weight: 1
        $x_1_2 = "C:\\clientpc\\otlook." wide //weight: 1
        $x_1_3 = "C:\\clientpc\\libmySQL50." wide //weight: 1
        $x_5_4 = "/cliente.jpg" wide //weight: 5
        $x_5_5 = "/libmySQL50.jpg" wide //weight: 5
        $x_5_6 = "/otlook.jpg" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ldrbanker_B_2147735236_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ldrbanker.B"
        threat_id = "2147735236"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ldrbanker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\clientpc\\dblog" wide //weight: 1
        $x_1_2 = "/dblog" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

