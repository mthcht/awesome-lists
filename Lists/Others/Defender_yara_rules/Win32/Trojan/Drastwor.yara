rule Trojan_Win32_Drastwor_A_2147599809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drastwor.A"
        threat_id = "2147599809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drastwor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*.star" ascii //weight: 1
        $x_1_2 = "starsdoor.com" ascii //weight: 1
        $x_1_3 = "&registration=" ascii //weight: 1
        $x_1_4 = "Explorer\\New Windows\\Allow" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_6 = "de lire le fichier" ascii //weight: 1
        $x_1_7 = "&nocache=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

