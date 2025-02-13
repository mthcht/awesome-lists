rule PWS_Win32_Kotwir_A_2147598352_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kotwir.A"
        threat_id = "2147598352"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kotwir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Toolhelp32ReadProcessMemory" ascii //weight: 1
        $x_1_2 = "Software\\Nexon\\Kingdom of the Winds" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Wizet\\MapleStory" ascii //weight: 1
        $x_5_4 = {3b 50 61 73 73 77 6f 72 64 3a 00 00 ff ff ff ff 11 00 00 00 3b 53 65 63 6f 6e 64 20 50 61 73 73 77 6f 72 64 3a 00}  //weight: 5, accuracy: High
        $x_5_5 = "&strPassword=" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

