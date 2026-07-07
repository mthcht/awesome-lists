rule Ransom_Win32_DeadLock_A_2147973060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DeadLock.A"
        threat_id = "2147973060"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DeadLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".dlock" ascii //weight: 1
        $x_1_2 = "dDlK" ascii //weight: 1
        $x_1_3 = "HOW_RECOVER" ascii //weight: 1
        $x_1_4 = "RECOVERY_CHAT" ascii //weight: 1
        $x_2_5 = {83 f9 0f 77 15 8b 91 ?? ?? ?? ?? 33 14 08 89 94}  //weight: 2, accuracy: Low
        $x_2_6 = {83 fb 07 77 12 8b 8b ?? ?? ?? ?? 33 0c 18 89 4c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

