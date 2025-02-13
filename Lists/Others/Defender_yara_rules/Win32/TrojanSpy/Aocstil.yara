rule TrojanSpy_Win32_Aocstil_A_2147692424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Aocstil.A"
        threat_id = "2147692424"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Aocstil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "show1234.com" ascii //weight: 1
        $x_1_2 = "46.151.52" ascii //weight: 1
        $x_1_3 = "add HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v" ascii //weight: 1
        $x_1_4 = {66 61 63 65 62 6f 6f 6b 2e 63 6f 6d [0-16] 26 63 64 67 3d [0-16] 70 61 73 73 77 6f 72 64}  //weight: 1, accuracy: Low
        $x_1_5 = {74 77 69 74 74 65 72 2e 63 6f 6d [0-16] 70 61 73 73 77 64 [0-16] 6c 6f 67 69 6e}  //weight: 1, accuracy: Low
        $x_1_6 = "&config={" wide //weight: 1
        $x_1_7 = "&codi" wide //weight: 1
        $x_1_8 = {8a d3 02 d2 8a c7 c0 e8 04 02 d2 24 03 02 c2 8a 55 fa 8a ca c0 e9 02 8a df c0 e2 06 02 55 fb 80 e1 0f c0 e3 04 32 cb 88 04 37 88 4c 37 01 88 54 37 02 83 c6 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

