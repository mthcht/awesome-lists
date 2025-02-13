rule Trojan_Win32_Reixecks_A_2147636861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reixecks.A"
        threat_id = "2147636861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reixecks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {84 c0 0f 84 ?? ?? 00 00 c7 45 ?? 72 65 6d 69 c7 45 ?? 78 73 69 64 c7 45 ?? 72 65 6d 69 c7 45 ?? 78 63 68 6b}  //weight: 2, accuracy: Low
        $x_1_2 = "mail.php?act=sent&to_id=" ascii //weight: 1
        $x_1_3 = "'friends':[" ascii //weight: 1
        $x_1_4 = "remixchk=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

