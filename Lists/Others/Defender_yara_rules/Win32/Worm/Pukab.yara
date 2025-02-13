rule Worm_Win32_Pukab_A_2147678997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pukab.A"
        threat_id = "2147678997"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pukab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 5a 6a 00 8d 85 2a fe ff ff 50 e8}  //weight: 1, accuracy: High
        $x_2_2 = "confbckp" ascii //weight: 2
        $x_1_3 = {73 63 72 65 65 6e 2e 6a 70 67 00}  //weight: 1, accuracy: High
        $x_1_4 = "nq.sytes.net/p/" ascii //weight: 1
        $x_1_5 = {72 75 6e 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_6 = "userandpc=%s&admin=%s&os=%s&hwid=%s&ownerid=%s&version=%s" ascii //weight: 1
        $x_1_7 = "system.lho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

