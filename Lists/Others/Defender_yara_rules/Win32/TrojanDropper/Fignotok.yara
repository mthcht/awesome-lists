rule TrojanDropper_Win32_Fignotok_A_2147647352_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Fignotok.gen!A"
        threat_id = "2147647352"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Fignotok"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_2 = "SbieDll" ascii //weight: 1
        $x_1_3 = "%s\\%s.exe" ascii //weight: 1
        $x_1_4 = {57 69 6e 64 6f 77 73 20 [0-5] 50 68 6f 74 6f 20 47 61 6c 6c 65 72 79}  //weight: 1, accuracy: Low
        $x_1_5 = "Picture can not be displayed." ascii //weight: 1
        $x_1_6 = {43 3a 5c 55 73 65 72 73 5c 73 5c 44 65 73 6b 74 6f 70 5c [0-8] 5c 43 6f 64 65 5c 6d 61 69 6e 5c 64 77 6e 5c 52 65 6c 65 61 73 65 5c 64 77 6e 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

