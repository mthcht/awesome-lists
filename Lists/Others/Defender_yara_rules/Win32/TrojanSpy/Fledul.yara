rule TrojanSpy_Win32_Fledul_2147646239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fledul"
        threat_id = "2147646239"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fledul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".#c%p%l%" ascii //weight: 1
        $x_1_2 = "\\*p*r#o#c%e%s%s%x%x%" ascii //weight: 1
        $x_1_3 = "g*e@t@m@a@i#l#" ascii //weight: 1
        $x_1_4 = "r%e%g* *a*d*d#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Fledul_B_2147646292_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fledul.gen!B"
        threat_id = "2147646292"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fledul"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "128x64x32.ini" ascii //weight: 1
        $x_1_2 = "hancook1.html" ascii //weight: 1
        $x_1_3 = "R40-33-DLL3273-24-42-24" ascii //weight: 1
        $x_1_4 = "J20-41-20-U35-23-20-39-24-22-23-37" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

