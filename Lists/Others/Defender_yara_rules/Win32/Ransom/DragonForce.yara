rule Ransom_Win32_DragonForce_SB_2147942133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DragonForce.SB!MTB"
        threat_id = "2147942133"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DragonForce"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_2 = "YOUR FILES HAVE BEEN ENCRYPTED! CHECK README" wide //weight: 1
        $x_1_3 = "wallpaper.bmp" wide //weight: 1
        $x_1_4 = "README" wide //weight: 1
        $x_1_5 = "encryption completed!" wide //weight: 1
        $x_1_6 = "Nul & Del /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

