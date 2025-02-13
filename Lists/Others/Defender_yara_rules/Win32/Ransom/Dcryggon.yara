rule Ransom_Win32_Dcryggon_A_2147722785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dcryggon.A"
        threat_id = "2147722785"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dcryggon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALREADY CRYPTED" wide //weight: 1
        $x_1_2 = "cmd /K ping 1.1.1.1 -n 1 -w 3000 > Nul & Del" wide //weight: 1
        $x_1_3 = ".qwqd\\\\shell\\\\open\\\\command" wide //weight: 1
        $x_1_4 = "Try to delete shadow copies..." wide //weight: 1
        $x_1_5 = "wscript \"C:\\\\Windows\\\\message.vbs" wide //weight: 1
        $x_1_6 = "Indy Pit Crew" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

