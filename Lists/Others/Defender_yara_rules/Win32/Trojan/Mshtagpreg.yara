rule Trojan_Win32_Mshtagpreg_B_2147772467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mshtagpreg.B"
        threat_id = "2147772467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mshtagpreg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "vbscript:Execute(" wide //weight: 1
        $x_1_3 = "CreateObject(" wide //weight: 1
        $x_1_4 = ").Run" wide //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
        $x_1_6 = "gp HKCU:\\Software" wide //weight: 1
        $x_1_7 = "|IEX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

