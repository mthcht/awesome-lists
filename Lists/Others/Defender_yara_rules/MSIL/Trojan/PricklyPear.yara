rule Trojan_MSIL_PricklyPear_A_2147894765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PricklyPear.A!dha"
        threat_id = "2147894765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PricklyPear"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\OneDriveUpdateCore.exe" wide //weight: 10
        $x_10_2 = "\\warAndDolphins.docx" wide //weight: 10
        $x_10_3 = "schtasks.exe /create /TN OneDriveStandal0ne /SC minute /mo 6 /tr" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

