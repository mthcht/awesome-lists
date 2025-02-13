rule Trojan_Win32_Zmem_A_2147739925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zmem.A"
        threat_id = "2147739925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zmem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your computer has been trashed by the MEMZ trojan" ascii //weight: 1
        $x_1_2 = "Your PC is fucked anyway" ascii //weight: 1
        $x_1_3 = "MakeMalwareGreatAgain" ascii //weight: 1
        $x_1_4 = "GET MLG ANTIVIRUS NEXT TIME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

