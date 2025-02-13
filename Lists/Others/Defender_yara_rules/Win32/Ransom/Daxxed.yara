rule Ransom_Win32_Daxxed_A_2147717735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Daxxed.A"
        threat_id = "2147717735"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Daxxed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 8b ec 8b 4d 0c c1 e9 02 8b 15 19 30 40 00 8b 75 08 8b fe ad 0f c8 33 c2 c1 c8 03 ab c1 c2 05}  //weight: 2, accuracy: High
        $x_1_2 = "LegalNoticeCaption" ascii //weight: 1
        $x_1_3 = "LegalNoticeText" ascii //weight: 1
        $x_1_4 = "Your server hacked" ascii //weight: 1
        $x_1_5 = ".dbf.pll.ntx.ovl.prn.chm.bmp.ini" ascii //weight: 1
        $x_1_6 = "ReadMe.TxT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Daxxed_A_2147717738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Daxxed.A!!Daxxed.gen!A"
        threat_id = "2147717738"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Daxxed"
        severity = "Critical"
        info = "Daxxed: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 8b ec 8b 4d 0c c1 e9 02 8b 15 19 30 40 00 8b 75 08 8b fe ad 0f c8 33 c2 c1 c8 03 ab c1 c2 05}  //weight: 2, accuracy: High
        $x_1_2 = "LegalNoticeCaption" ascii //weight: 1
        $x_1_3 = "LegalNoticeText" ascii //weight: 1
        $x_1_4 = "Your server hacked" ascii //weight: 1
        $x_1_5 = ".dbf.pll.ntx.ovl.prn.chm.bmp.ini" ascii //weight: 1
        $x_1_6 = "ReadMe.TxT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

