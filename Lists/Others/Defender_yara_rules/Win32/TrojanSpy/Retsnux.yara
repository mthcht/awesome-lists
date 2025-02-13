rule TrojanSpy_Win32_Retsnux_A_2147696310_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Retsnux.A"
        threat_id = "2147696310"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Retsnux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "out_file = %A_Startup%\\netwin.exe" ascii //weight: 1
        $x_1_2 = "Failed to create 'netwin' certificate." ascii //weight: 1
        $x_1_3 = "FileAppend, %k% , %A_AppData%\\Microsoft\\data\\NETUSR" ascii //weight: 1
        $x_1_4 = {73 41 74 74 61 63 68 [0-5] 3d [0-5] 25 41 5f 41 70 70 44 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 5c 64 61 74 61 5c 4e 45 54 55 53 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

