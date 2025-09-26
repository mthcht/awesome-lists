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

rule Ransom_Win32_DragonForce_E_2147953253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DragonForce.E"
        threat_id = "2147953253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DragonForce"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 75 00 6e 00 64 00 65 00 72 00 3a 00 20 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 69 00 73 00 20 00 65 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 3a 00 20 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 00 65 00 6e 00 61 00 6d 00 69 00 6e 00 67 00 3a 00 20 00 25 00 73 00 20 00 2c 00 20 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 65 00 74 00 74 00 69 00 6e 00 67 00 20 00 25 00 73 00 20 00 74 00 6f 00 20 00 25 00 73 00 20 00 77 00 69 00 74 00 68 00 20 00 6c 00 65 00 6e 00 20 00 25 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 00 75 00 6e 00 20 00 54 00 72 00 69 00 67 00 67 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "C:\\Users\\admin\\Desktop\\cerbi\\Release\\cryptor.pdb" ascii //weight: 1
        $x_1_7 = {99 f7 fe 8d 42 7f 99 f7 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

