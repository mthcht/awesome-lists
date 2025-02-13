rule Ransom_MSIL_Falock_A_2147716233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Falock.A"
        threat_id = "2147716233"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Falock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/payment.html" ascii //weight: 1
        $x_1_2 = "/stat.html" ascii //weight: 1
        $x_1_3 = "SHADOW_COPY_DIRS" wide //weight: 1
        $x_1_4 = "CODE_DOWNLOAD_DISABLED" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Falock_B_2147723290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Falock.B"
        threat_id = "2147723290"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Falock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 2e 00 4b 01 4d 00 2e 00 53 01 4d 00 2e 00 5b 02 cd 00 43 00 d3 01 44 00 43 00 53 01 4d 00 69}  //weight: 1, accuracy: High
        $x_1_2 = "32372E30332E32303136|01|N7" wide //weight: 1
        $x_1_3 = {21 00 c8 00 cd 00 d1 00 d2 00 d0 00 d3 00 ca 00 d6 00 c8 00 df 00 21 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: High
        $x_1_4 = ".zcrypt" wide //weight: 1
        $x_1_5 = "System.Security.Permissions.IUnrestrictedPermission" wide //weight: 1
        $x_2_6 = "SHADOW_COPY_DIRS" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

