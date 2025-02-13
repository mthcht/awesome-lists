rule Trojan_Win32_Calishoo_A_2147648364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Calishoo.A"
        threat_id = "2147648364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Calishoo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Engellendikten sonra tekrar calistirildi!" ascii //weight: 2
        $x_1_2 = "/w/1stupload.php" ascii //weight: 1
        $x_2_3 = "/V syscheck /D \"\\\"" ascii //weight: 2
        $x_2_4 = "conteudo=" ascii //weight: 2
        $x_2_5 = {53 69 66 72 65 6c 65 72 69 04 00 4d 73 6e 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

