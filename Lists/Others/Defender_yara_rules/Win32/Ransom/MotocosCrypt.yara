rule Ransom_Win32_MotocosCrypt_PA_2147782008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MotocosCrypt.PA!MTB"
        threat_id = "2147782008"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MotocosCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Readme.txt" wide //weight: 3
        $x_3_2 = "Motocos_bot" wide //weight: 3
        $x_3_3 = "Motocos_Readme.txt" wide //weight: 3
        $x_3_4 = "Ransomware_Readme.txt" wide //weight: 3
        $x_1_5 = "Clear-EventLog -LogName application, system, security" wide //weight: 1
        $x_1_6 = "vssadmin.exe delete shadows /all /quiet;wmic shadowcopy delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

