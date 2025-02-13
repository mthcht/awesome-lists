rule Worm_Win32_Lefgroo_C_2147616704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lefgroo.C"
        threat_id = "2147616704"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lefgroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "infectar tres niveles de subcarpetas de una raiz\\Project1" wide //weight: 4
        $x_4_2 = "Creando Un Virus" wide //weight: 4
        $x_2_3 = {53 75 53 6f 66 74 00}  //weight: 2, accuracy: High
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = {43 61 72 70 65 74 61 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

