rule TrojanSpy_Win32_Sikfoban_A_2147716464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sikfoban.A"
        threat_id = "2147716464"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sikfoban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e2 47 0b 00 0f 84 c7 04 00 00 81 3d ?? ?? ?? 00 0d 8c 00 00 0f 84 b7 04 00 00 8d 4d d4 8b 15}  //weight: 2, accuracy: Low
        $x_1_2 = "FINILIDIFHY" wide //weight: 1
        $x_1_3 = "OHDGTIDHVJBIMJAJBIDHQJDIJITIQIKID" wide //weight: 1
        $x_1_4 = "QIUIOJCIXIOIVGOGNGJINIVIV" wide //weight: 1
        $x_1_5 = "QHYISJCJEJFIKIVHDIVIVIYIMHHJI" wide //weight: 1
        $x_1_6 = "XIHJJJAJLIVIAJJJGITIVJKJKHWIVJEJGJJJQ" wide //weight: 1
        $x_1_7 = "GGUIRIEIAITIEHKIEIMIOITIEHMIHIRIEIAID" wide //weight: 1
        $x_1_8 = "IHJIRIGIPHKITIQIEIGIUIU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

