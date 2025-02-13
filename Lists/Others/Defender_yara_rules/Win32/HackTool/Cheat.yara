rule HackTool_Win32_Cheat_A_2147511591_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Cheat.A"
        threat_id = "2147511591"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cheat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www10.brinkster.com/shohdiissad/db.asp" wide //weight: 1
        $x_1_2 = "GigaByte.exe" wide //weight: 1
        $x_1_3 = "SYSTEM\\radmin\\v2.0\\server\\parameters" wide //weight: 1
        $x_1_4 = "/pass:shohdielsheemy" wide //weight: 1
        $x_1_5 = "F:\\shohdi.vb\\hack\\version1.1\\Explorer.vbp" wide //weight: 1
        $x_1_6 = "/pass:hellomine" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

