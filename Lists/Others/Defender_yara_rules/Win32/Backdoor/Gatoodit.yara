rule Backdoor_Win32_Gatoodit_A_2147621259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gatoodit.A"
        threat_id = "2147621259"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatoodit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 fb 01 eb 0b 46 83 fe 03 7e 05 be 01 00 00 00 80 7d fb 00 0f 84}  //weight: 2, accuracy: High
        $x_2_2 = {8a 00 2c 31 74 0e fe c8 74 16 fe c8 74 1e fe c8 74 23 eb 23}  //weight: 2, accuracy: High
        $x_1_3 = "botid.txt" ascii //weight: 1
        $x_1_4 = "update.php?id=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

