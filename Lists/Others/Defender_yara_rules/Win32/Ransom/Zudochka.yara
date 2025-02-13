rule Ransom_Win32_Zudochka_A_2147756600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zudochka.A!MSR"
        threat_id = "2147756600"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zudochka"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files have been encrypted!" ascii //weight: 1
        $x_1_2 = "DECRYPT_FILES.TXT" ascii //weight: 1
        $x_1_3 = "\\HOW TO RESTORE ENCRYPTED FILES.TXT" ascii //weight: 1
        $x_1_4 = "decryptor and a unique decryption key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Zudochka_D_2147756620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zudochka.D!MTB"
        threat_id = "2147756620"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zudochka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!!FAQ for Decryption!!.txt" wide //weight: 1
        $x_1_2 = "CryptApp.pdb" ascii //weight: 1
        $x_1_3 = "All your files are encrypted" ascii //weight: 1
        $x_1_4 = "Do not rename encrypted files." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Zudochka_AR_2147756636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zudochka.AR!MTB"
        threat_id = "2147756636"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zudochka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".backupdb" ascii //weight: 1
        $x_1_2 = "\\System Volume Information\\" ascii //weight: 1
        $x_2_3 = "%s\\Readme.README" ascii //weight: 2
        $x_2_4 = "n.locked" ascii //weight: 2
        $x_2_5 = "To get all your data back contact us:" ascii //weight: 2
        $x_2_6 = "C:\\WINDOWS\\SYSTEM32\\drivers\\root\\system\\*.*" ascii //weight: 2
        $x_2_7 = "C:\\WINDOWS\\SYSTEM32\\drivers\\gmreadme.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Zudochka_V_2147757176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zudochka.V!MTB"
        threat_id = "2147757176"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zudochka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 ec 8b 55 ec 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 c1 c0 0f 08 00 89 0d ?? ?? ?? ?? 8b 45 ec 8b e5}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 ?? a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 83 c2 ?? ff 35 ?? ?? ?? ?? 8f 45 ?? 8b ca 31 4d ?? 8b 45 ?? c7 05 [0-10] 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Zudochka_G_2147765552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zudochka.G!MSR"
        threat_id = "2147765552"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zudochka"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec a1 04 c0 41 00 83 e0 1f 6a 20 59 2b c8 8b 45 08 d3 c8 33 05 04 c0 41 00 5d}  //weight: 1, accuracy: High
        $x_1_2 = {8b ec 81 ec 20 0a 00 00 a1 04 c0 41 00 33 c5 89 45 f8 53}  //weight: 1, accuracy: High
        $x_1_3 = "LockBit Decryptor 1.3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

