rule Ransom_Win32_Zeoticus_PA_2147771268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zeoticus.PA!MTB"
        threat_id = "2147771268"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeoticus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@tutanota.com" wide //weight: 1
        $x_1_2 = "All your files has been encrypted" wide //weight: 1
        $x_1_3 = "README.html" wide //weight: 1
        $x_1_4 = "%s%x%x%x%x.zeoticus2" wide //weight: 1
        $x_1_5 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Zeoticus_RZ_2147775547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Zeoticus.RZ!MTB"
        threat_id = "2147775547"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeoticus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\mainProduct(old)\\x86_bild_cryptor\\shell_gen\\Release\\data_protect2.pdb" ascii //weight: 1
        $x_1_2 = "2021FIRST@tutanota.com" ascii //weight: 1
        $x_1_3 = "2021FIRST@protonmail.com" ascii //weight: 1
        $x_1_4 = ".DEFAULT\\Keyboard Layout\\Preload" wide //weight: 1
        $x_1_5 = "%s /node:\"%ws\" /user:\"%ws\" /password:\"%ws\"" wide //weight: 1
        $x_1_6 = "%s%x%x%x%x.zeoticus2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

