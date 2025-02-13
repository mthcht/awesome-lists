rule Ransom_Win32_Roodcol_2147728979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Roodcol"
        threat_id = "2147728979"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Roodcol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "189"
        strings_accuracy = "High"
    strings:
        $x_54_1 = "copy \"Locdoor.exe\" \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\temp00000000.exe\"" ascii //weight: 54
        $x_54_2 = "echo Your computer's files have been encrypted to Locdoor Ransomware!" ascii //weight: 54
        $x_54_3 = "start http://9w37hde92oqvcew235.creatorlink.net/" ascii //weight: 54
        $x_54_4 = "364apytRKNUXFmVsk5z8Wf1T7tYcoD1RTZ" ascii //weight: 54
        $x_27_5 = "Your computer's important files have been encrypted!" ascii //weight: 27
        $x_1_6 = "ren *.mp4 *.door1" ascii //weight: 1
        $x_1_7 = "ren *.avi *.door2" ascii //weight: 1
        $x_1_8 = "ren *.mp3 *.doo3r" ascii //weight: 1
        $x_1_9 = "ren *.txt *.door4" ascii //weight: 1
        $x_1_10 = "ren *.hwp *.doo5r" ascii //weight: 1
        $x_1_11 = "ren *.pptx *.door6" ascii //weight: 1
        $x_1_12 = "ren *.docx *.door7" ascii //weight: 1
        $x_1_13 = "ren *.xlsx *.door8" ascii //weight: 1
        $x_1_14 = "ren *.html *.door9" ascii //weight: 1
        $x_1_15 = "ren *.xml *.door10" ascii //weight: 1
        $x_1_16 = "ren *.amr *.door11" ascii //weight: 1
        $x_1_17 = "ren *.mov *.door12" ascii //weight: 1
        $x_1_18 = "ren *.mkv *.door13" ascii //weight: 1
        $x_1_19 = "ren *.wav *.door14" ascii //weight: 1
        $x_1_20 = "ren *.wmv *.door15" ascii //weight: 1
        $x_1_21 = "ren *.wma *.door16" ascii //weight: 1
        $x_1_22 = "ren *.tar *.door17" ascii //weight: 1
        $x_1_23 = "ren *.png *.door18" ascii //weight: 1
        $x_1_24 = "ren *.jpg *.door19" ascii //weight: 1
        $x_1_25 = "ren *.jpeg *.door20" ascii //weight: 1
        $x_1_26 = "ren *.bmp *.door21" ascii //weight: 1
        $x_1_27 = "ren *.rar *.door22" ascii //weight: 1
        $x_1_28 = "ren *.jar *.door23" ascii //weight: 1
        $x_1_29 = "ren *.zip *.door24" ascii //weight: 1
        $x_1_30 = "ren *.7z *.door25" ascii //weight: 1
        $x_1_31 = "ren *.iso *.door26" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_54_*) and 1 of ($x_27_*))) or
            ((4 of ($x_54_*))) or
            (all of ($x*))
        )
}

