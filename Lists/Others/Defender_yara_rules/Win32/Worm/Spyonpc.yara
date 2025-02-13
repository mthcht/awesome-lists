rule Worm_Win32_Spyonpc_A_2147685080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Spyonpc.A"
        threat_id = "2147685080"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyonpc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%02d%02d%02d %02d%02d%02d %02d%02d%02d" ascii //weight: 1
        $x_1_2 = "%33s%s\\%s" ascii //weight: 1
        $x_1_3 = "={645FF040-5081-101B-9F08-00AA002F954E}" ascii //weight: 1
        $x_1_4 = "tup35.exe" ascii //weight: 1
        $x_2_5 = "tx_Sp_On_PC_1_2_8" ascii //weight: 2
        $x_2_6 = {05 c5 4e f1 07 89 04 ?? 46 83 fe 04 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

