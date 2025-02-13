rule TrojanDropper_Win32_Redline_AYA_2147927995_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Redline.AYA!MTB"
        threat_id = "2147927995"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "iplogger.org" wide //weight: 2
        $x_1_2 = ">AUTOHOTKEY SCRIPT<" wide //weight: 1
        $x_1_3 = "Could not launch WindowSpy.ahk or AU3_Spy.exe" wide //weight: 1
        $x_1_4 = "%USERPROFILE%\\Desktop\\Invoice.docx" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Folders" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

