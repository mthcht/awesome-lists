rule Trojan_Win64_Kriskynote_A_2147708106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kriskynote.A!dha"
        threat_id = "2147708106"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kriskynote"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AyrarbiLdaoL" ascii //weight: 1
        $x_1_2 = "Install_uac" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters" ascii //weight: 1
        $x_1_4 = {00 49 6e 73 74 61 6c 6c 00 44 65 6c 65 74 65 46 00}  //weight: 1, accuracy: High
        $x_1_5 = {8a 04 31 34 36 8a d0 80 e2 0f c0 e2 04 c0 e8 04 02 d0 88 14 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

