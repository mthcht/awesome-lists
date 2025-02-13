rule Ransom_Win32_Fermyrypt_A_2147722827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Fermyrypt.A"
        threat_id = "2147722827"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Fermyrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\wp_encrypt.pdb" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS\\SYSTEM32\\*.dll" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" wide //weight: 1
        $x_2_4 = {0f b6 04 07 33 c6 c1 ee 08 0f b6 c0 33 34 83 8b 44 24 10 33 f2 47 3b fd 7c e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

