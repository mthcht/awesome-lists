rule Backdoor_Win32_Ginwui_E_2147611443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ginwui.E"
        threat_id = "2147611443"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ginwui"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 57 50 e8 03 00 00 00 e9 eb 04 58 40 50 c3}  //weight: 10, accuracy: High
        $x_1_2 = "AppInit_DLLs" ascii //weight: 1
        $x_1_3 = "%s\\drivers\\%s" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = {47 55 49 53 76 72 44 6c 6c 2e 64 6c 6c 00 44 6f 48 6f 6f 6b 00 44 6f 54 65 73 74}  //weight: 1, accuracy: High
        $x_1_6 = "WINGUIS" ascii //weight: 1
        $x_1_7 = "\\GUISvrDll\\Release\\GUISvrDll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

