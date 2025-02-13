rule Ransom_Win32_Ruqwili_A_2147706794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ruqwili.A"
        threat_id = "2147706794"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ruqwili"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<a href=\"mailto:filesos@yeah.net\">filesos@yeah.net</a>" ascii //weight: 1
        $x_1_2 = {7b 22 65 6d 61 69 6c 22 3a 22 [0-16] 40 [0-16] 2e [0-4] 22 2c 22 6b 65 79 22 3a 22 [0-16] 22 2c 22 65 78 74 22 3a 22 [0-16] 22 2c 22 68 61 73 68 54 79 70 65 22 3a ?? 2c 22 63 69 70 68 65 72 54 79 70 65 22 3a ?? 2c 22 63 6d 54 79 70 65 22 3a ?? 2c 22 73 61 6c 74 53 69 7a 65 22 3a [0-5] 2c 22 43 74 22 3a ?? 2c 22 48 74 22 3a ?? 2c 22 4b 65 79 53 74 72 22 3a 22 [0-16] 22 7d 00}  //weight: 1, accuracy: Low
        $x_1_3 = "*.doc,*.docx,*.docm,*.odt,*.xls,*.xlsx,*.xlsm,*.csv,*.xlsb,*.ods,*.sxc,*.ppt,*.pptx,*.pptm,*.odp,*.dbf,*.mdb,*.ACCDA,*.ACCDB," ascii //weight: 1
        $x_1_4 = ".ExecQuery(\"Select * From Win32_ShadowCopy\")" ascii //weight: 1
        $x_1_5 = {c2 f1 e5 20 e2 e0 f8 e8 20 f4 e0 e9 eb fb 20 e7 e0 f8 e8 f4 f0 ee e2 e0 ed fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

