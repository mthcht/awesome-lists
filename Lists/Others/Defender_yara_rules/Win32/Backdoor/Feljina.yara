rule Backdoor_Win32_Feljina_A_2147636168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Feljina.A"
        threat_id = "2147636168"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Feljina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {01 00 83 c4 0c c6 45 ec a2 c6 45 ed 13 c6 45 ee ?? c6 45 ef}  //weight: 8, accuracy: Low
        $x_4_2 = "lr:%d,%d,%d;la:%d,%d,%d;cr:%d,%d,%d" ascii //weight: 4
        $x_4_3 = "%d,%d,%d,xx:%dkk:0x%x" ascii //weight: 4
        $x_2_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GoldenKey" ascii //weight: 2
        $x_1_5 = "ans_work" ascii //weight: 1
        $x_1_6 = "GetHtoS" ascii //weight: 1
        $x_1_7 = "GetS_PUBKEY" ascii //weight: 1
        $x_1_8 = "IDnotEQU" ascii //weight: 1
        $x_1_9 = "jianjine" ascii //weight: 1
        $x_1_10 = "newjianjine" ascii //weight: 1
        $x_1_11 = "Send_S_To_H" ascii //weight: 1
        $x_1_12 = "readset_info" ascii //weight: 1
        $x_1_13 = "Testcardon" ascii //weight: 1
        $x_1_14 = "ask_work" ascii //weight: 1
        $x_1_15 = "backHard_info" ascii //weight: 1
        $x_1_16 = "exeyeji" ascii //weight: 1
        $x_1_17 = "new_exeyeji" ascii //weight: 1
        $x_1_18 = "setjihao" ascii //weight: 1
        $x_1_19 = "tmpshangji" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_4_*) and 12 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 12 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*) and 10 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 8 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

