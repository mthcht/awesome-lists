rule TrojanSpy_Win32_Svelta_A_2147627561_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Svelta.A"
        threat_id = "2147627561"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Svelta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".bancobrasil.com.br/aapf" ascii //weight: 3
        $x_1_2 = "HookyBH attached:" ascii //weight: 1
        $x_1_3 = "senhaConta" ascii //weight: 1
        $x_1_4 = "/post.php" ascii //weight: 1
        $x_1_5 = "PR_Write" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

