rule TrojanDropper_Win32_Lydo_B_2147596424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Lydo.B"
        threat_id = "2147596424"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Lydo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LYLOADER.EXE" ascii //weight: 1
        $x_1_2 = "LYMANGR.DLL" wide //weight: 1
        $x_1_3 = "MSDEG32.DLL" wide //weight: 1
        $x_1_4 = "REGKEY.HIV" wide //weight: 1
        $x_1_5 = "LoadResource" ascii //weight: 1
        $x_1_6 = "RtlZeroMemory" ascii //weight: 1
        $x_1_7 = "WriteFile" ascii //weight: 1
        $x_10_8 = {68 64 20 40 00 68 6b 20 40 00 ff 75 fc e8 b6 01 00 00 0b c0 74 73 89 45 f8 50 ff 75 fc e8 e2 01 00 00 89 45 f0 ff 75 f8 ff 75 fc e8 bc 01 00 00 0b c0 74 55 50 e8 b8 01 00 00 0b c0 74 4b 89 45 ec 6a 00 6a 20 6a 02 6a 00 6a 00 68 00 00 00 40 68 00 30 40 00 e8 5c 01 00 00 0b c0 74 2b 89 85 e4 fe ff ff 6a 00 8d 85 e0 fe ff ff 50 ff 75 f0 ff 75 ec ff b5 e4 fe ff ff e8 8c 01 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

