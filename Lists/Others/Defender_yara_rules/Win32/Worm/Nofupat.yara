rule Worm_Win32_Nofupat_A_2147598333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nofupat.A"
        threat_id = "2147598333"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nofupat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Visual Studio\\VB98" ascii //weight: 1
        $x_1_2 = "scvhost" ascii //weight: 1
        $x_1_3 = "astry.exe" wide //weight: 1
        $x_1_4 = "network.exe" wide //weight: 1
        $x_1_5 = "update\\scvhost.vbp" wide //weight: 1
        $x_1_6 = "RegOpenKeyExA" ascii //weight: 1
        $x_1_7 = "RegSetValueExA" ascii //weight: 1
        $x_1_8 = "RegCloseKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

