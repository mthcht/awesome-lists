rule Rogue_Win32_Tiropot_169000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Tiropot"
        threat_id = "169000"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Tiropot"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ANTIPROTECT_MONITOR" wide //weight: 2
        $x_2_2 = "ANTIPROTECT_UPDATE" ascii //weight: 2
        $x_1_3 = "antiprotect.co.kr/pay/payment.php" wide //weight: 1
        $x_1_4 = "/app/count.php?kind=run&pid=[PID]" wide //weight: 1
        $x_1_5 = "/app/licensechk.php" wide //weight: 1
        $x_1_6 = "/app/app_set.php?pid=[PID]" wide //weight: 1
        $x_1_7 = "/START:PCUSAGE:%d" wide //weight: 1
        $x_1_8 = "file.antiprotect.co.kr/total/AntiProtectUpdate.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

