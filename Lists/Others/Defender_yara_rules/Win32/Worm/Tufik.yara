rule Worm_Win32_Tufik_A_2147545393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tufik.A"
        threat_id = "2147545393"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tufik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 41 64 76 4b 65 79 2e 64 6c 6c 00 5c 73 65 72 69 61 6c 2e 64 6c 6c 00 68 74 74 70 3a 2f 2f 74 75 66 65 69 35 30 33 2e 35 31 2e 6e 65 74 2f 62 75 74 2e 63 73 00 68 74 74 70 3a 2f 2f 74 75 66 65 69 35 30 33 2e 68 6f 6d 65 34 75 2e 63 68 69 6e 61 2e 63 6f 6d 2f 62 75 74 2e 63}  //weight: 1, accuracy: High
        $x_1_2 = "FtpGetFileA" ascii //weight: 1
        $x_1_3 = "InternetReadFile" ascii //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "Program Files\\Microsoft Visual Studio\\VB98\\lhw\\XDD\\XDD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

