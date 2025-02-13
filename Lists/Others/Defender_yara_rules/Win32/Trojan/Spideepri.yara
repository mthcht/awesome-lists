rule Trojan_Win32_Spideepri_A_2147723098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spideepri.A"
        threat_id = "2147723098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spideepri"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{A19F8F88-F91E-4e49-2222-BD21AB39D1BB}" wide //weight: 1
        $x_1_2 = "speeditupfree.exe" wide //weight: 1
        $x_1_3 = "speeditupfree.com" wide //weight: 1
        $x_1_4 = "MicroSmarts LLC" wide //weight: 1
        $x_1_5 = "www.microsmartsllc.com" wide //weight: 1
        $x_1_6 = "SpeetItUpFree" wide //weight: 1
        $x_1_7 = "SpeedNewASK\\Debug\\spdfrmon.pdb" ascii //weight: 1
        $x_1_8 = "SpeedItup Type Library" ascii //weight: 1
        $x_1_9 = "SpeedItup Interface" ascii //weight: 1
        $x_1_10 = "spdfrmon.Gate" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

