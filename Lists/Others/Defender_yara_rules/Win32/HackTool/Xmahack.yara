rule HackTool_Win32_Xmahack_A_2147648800_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Xmahack.A"
        threat_id = "2147648800"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Xmahack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Inject Cheat" ascii //weight: 1
        $x_1_2 = "Xmaho.vbp" wide //weight: 1
        $x_1_3 = "Password salah" wide //weight: 1
        $x_1_4 = "Failed to Write DLL to Process!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

