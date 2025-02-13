rule Trojan_Win32_Cobast_YL_2147744627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cobast.YL!MSR"
        threat_id = "2147744627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobast"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "virus_load.exe" wide //weight: 1
        $x_1_2 = "GETPASSWORD1" wide //weight: 1
        $x_1_3 = "REPLACEFILEDLG" wide //weight: 1
        $x_1_4 = "hed20.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

