rule Ransom_Win32_Exmas_A_2147719679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exmas.A.A"
        threat_id = "2147719679"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exmas"
        severity = "Critical"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "||doc||docb||docm||docx||dot||dotm||" ascii //weight: 1
        $x_1_2 = "||ppsx||ppt||pptm||pptx||" ascii //weight: 1
        $x_1_3 = "||xls||xlsb||xlsm||xlsx||" ascii //weight: 1
        $x_1_4 = "%userid%" ascii //weight: 1
        $x_1_5 = "cmd /c vssadmin delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Exmas_A_2147719930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exmas.A!!Exmas.gen!A"
        threat_id = "2147719930"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exmas"
        severity = "Critical"
        info = "Exmas: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "||doc||docb||docm||docx||dot||dotm||" ascii //weight: 1
        $x_1_2 = "||ppsx||ppt||pptm||pptx||" ascii //weight: 1
        $x_1_3 = "||xls||xlsb||xlsm||xlsx||" ascii //weight: 1
        $x_2_4 = "cmd /c vssadmin delete shadows /all /quiet" ascii //weight: 2
        $x_1_5 = "PAY TO RECOVER YOUR DATA" ascii //weight: 1
        $x_1_6 = "ChangedFileExt:" ascii //weight: 1
        $x_1_7 = "DefaultCryptKey:" ascii //weight: 1
        $x_1_8 = "isCryptFileNames:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

