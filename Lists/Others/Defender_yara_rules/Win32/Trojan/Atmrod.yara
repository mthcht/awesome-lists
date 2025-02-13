rule Trojan_Win32_Atmrod_B_2147735625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Atmrod.B"
        threat_id = "2147735625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Atmrod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "atmapp.exe" ascii //weight: 1
        $x_1_2 = "c:\\atm\\1" ascii //weight: 1
        $x_1_3 = "Xfs::QueryCashUnitsFromAtm4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

