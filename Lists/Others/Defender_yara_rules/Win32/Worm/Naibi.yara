rule Worm_Win32_Naibi_A_2147711570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Naibi.A"
        threat_id = "2147711570"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Naibi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\WINDOWS\\system32\\wscript.exe  /e:VBScript.Encode  iphon.mp3" wide //weight: 1
        $x_1_2 = "cmd.exe /c explorer.exe %cd%" wide //weight: 1
        $x_1_3 = "Nouveaudossier" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

