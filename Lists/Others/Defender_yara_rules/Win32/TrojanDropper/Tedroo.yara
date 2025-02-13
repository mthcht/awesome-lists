rule TrojanDropper_Win32_Tedroo_B_2147601776_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tedroo.B"
        threat_id = "2147601776"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "257"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "del %" ascii //weight: 100
        $x_100_2 = "if exist %1 goto " ascii //weight: 100
        $x_10_3 = "\\\\.\\DefLib" wide //weight: 10
        $x_10_4 = "SysLibrary" wide //weight: 10
        $x_10_5 = "\\drivers\\etc\\hosts" wide //weight: 10
        $x_10_6 = "explorer.exe" wide //weight: 10
        $x_10_7 = "Firewall auto setup" ascii //weight: 10
        $x_1_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_9 = "Software\\Microsoft\\Internet Explorer\\Security" ascii //weight: 1
        $x_1_10 = "ZwLoadDriver" ascii //weight: 1
        $x_1_11 = "LoadLibraryExW" ascii //weight: 1
        $x_1_12 = "RYCreateWindowExW" ascii //weight: 1
        $x_1_13 = "GetSystemDirectoryW" ascii //weight: 1
        $x_1_14 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_15 = "MMWritePrivateProfileStringA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 5 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Tedroo_C_2147633328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tedroo.C"
        threat_id = "2147633328"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 cd 97 8e df 8b dd c2 c4 c1 8f dc df 93 c0 d2 ca 84 9f c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

