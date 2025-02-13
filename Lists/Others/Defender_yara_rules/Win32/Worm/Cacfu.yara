rule Worm_Win32_Cacfu_E_2147617537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cacfu.E"
        threat_id = "2147617537"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cacfu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 00 74 65 6c 2e 78 6c 73 00 45 78 63 65 6c 00 00 b9 a4 b3 cc 31 00 00}  //weight: 10, accuracy: High
        $x_10_2 = "SQLOLEDB.1" wide //weight: 10
        $x_10_3 = "Integrated Security=SSPI;" wide //weight: 10
        $x_1_4 = ".dbo.gl_accsum where iperiod=" wide //weight: 1
        $x_1_5 = "select iyear from ua_period where cAcc_id=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

