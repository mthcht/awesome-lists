rule Ransom_Win32_CryptoLemPiz_A_2147716178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/CryptoLemPiz.A"
        threat_id = "2147716178"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoLemPiz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ";boot.ini;NTDETECT.COM;Bootfont.bin;ntldr;bootmgr;BOOTNXT;BOOTSECT.BAK;NTUSER.DAT;PDOXUSRS.NET;" ascii //weight: 2
        $x_1_2 = " INFO" ascii //weight: 1
        $x_1_3 = {67 00 6f 00 74 00 6f 00 20 00 74 00 72 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 74 00 65 00 6d 00 70 00 30 00 30 00 30 00 30 00 30 00 30 00 2e 00 74 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_2_6 = {43 72 79 70 74 4f 4e 5c 6c 6f 63 6b 5c 78 41 45 53 2e 70 61 73 00}  //weight: 2, accuracy: High
        $x_2_7 = {8b c3 e8 98 ff ff ff 88 04 2e 45 8a 04 2e 84 c0 75 ec 8b c6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

