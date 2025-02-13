rule TrojanDropper_Win32_Alphabet_2147594075_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Alphabet"
        threat_id = "2147594075"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Alphabet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Microcoft" ascii //weight: 2
        $x_1_2 = "c:\\temp2.bat" ascii //weight: 1
        $x_1_3 = "bfxtray.exe" ascii //weight: 1
        $x_1_4 = "webal.exe" ascii //weight: 1
        $x_1_5 = "smanager" ascii //weight: 1
        $x_1_6 = "C:\\WINDOWS\\avp.exe" ascii //weight: 1
        $x_1_7 = "\\avp.exe" ascii //weight: 1
        $x_1_8 = "%s\\%ld.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

