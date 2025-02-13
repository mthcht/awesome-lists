rule Trojan_Win32_Dibizor_A_2147716341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dibizor.A!bit"
        threat_id = "2147716341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dibizor"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zgokr00.exe" wide //weight: 1
        $x_1_2 = "Dibifu_9\\vshost32.exe" wide //weight: 1
        $x_1_3 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

