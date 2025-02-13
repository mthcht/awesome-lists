rule TrojanDropper_Win32_Strumapine_A_2147717227_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Strumapine.A"
        threat_id = "2147717227"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Strumapine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\a.vbe" wide //weight: 1
        $x_1_2 = "ConfigSecurityPolicy.exename" wide //weight: 1
        $x_1_3 = "ProtectionManagement_Uninstall.exename" wide //weight: 1
        $x_1_4 = "http://e-defender.com.br/includes/a/tr/katia.rar" wide //weight: 1
        $x_1_5 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-96] 2f 00 64 00 64 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

