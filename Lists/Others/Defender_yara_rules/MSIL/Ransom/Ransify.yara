rule Ransom_MSIL_Ransify_BB_2147853277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ransify.BB"
        threat_id = "2147853277"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ransify"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "84"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Lockify.llog" wide //weight: 20
        $x_20_2 = "api/address/transaction" wide //weight: 20
        $x_20_3 = "/k ping 0 & del" wide //weight: 20
        $x_20_4 = "encryptDirectory" ascii //weight: 20
        $x_1_5 = ".mov" wide //weight: 1
        $x_1_6 = ".pptx" wide //weight: 1
        $x_1_7 = ".xlsx" wide //weight: 1
        $x_1_8 = ".java" wide //weight: 1
        $x_1_9 = ".cpp" wide //weight: 1
        $x_1_10 = ".zip" wide //weight: 1
        $x_1_11 = ".rar" wide //weight: 1
        $x_1_12 = ".pdf" wide //weight: 1
        $x_1_13 = ".sql" wide //weight: 1
        $x_1_14 = ".asm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Ransify_BC_2147853278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ransify.BC"
        threat_id = "2147853278"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ransify"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 10
        $x_10_2 = "cipher.exe /W" wide //weight: 10
        $x_10_3 = "fsutil usn deletejournal /D" wide //weight: 10
        $x_10_4 = "README-VIAGRA-" wide //weight: 10
        $x_10_5 = "EnCiPhErEd-" wide //weight: 10
        $x_10_6 = "PDF_Invoice_" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Ransify_BD_2147853279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ransify.BD"
        threat_id = "2147853279"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ransify"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "105"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "uploadToFTP" ascii //weight: 20
        $x_20_2 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 20
        $x_20_3 = "/C ping 8.8.8.8 -n 1 -w" wide //weight: 20
        $x_20_4 = "Select * from Win32_Processor" wide //weight: 20
        $x_20_5 = "encryptDirectory" ascii //weight: 20
        $x_1_6 = ".txt" wide //weight: 1
        $x_1_7 = ".pptx" wide //weight: 1
        $x_1_8 = ".xlsx" wide //weight: 1
        $x_1_9 = ".java" wide //weight: 1
        $x_1_10 = ".cpp" wide //weight: 1
        $x_1_11 = ".zip" wide //weight: 1
        $x_1_12 = ".rar" wide //weight: 1
        $x_1_13 = ".pdf" wide //weight: 1
        $x_1_14 = ".sql" wide //weight: 1
        $x_1_15 = ".doc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_20_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

