rule Ransom_MSIL_Cerber_TA_2147745006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Cerber.TA!MSR"
        threat_id = "2147745006"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerber"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "C:\\Users\\user\\Desktop\\WindowsApplication1\\WindowsApplication1\\obj\\x86\\Release\\Windows Application.pdb" ascii //weight: 4
        $x_1_2 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\sochost.exe" wide //weight: 1
        $x_1_3 = "\\Start Menu\\Programs\\Startup\\sochost.exe" wide //weight: 1
        $x_1_4 = "\\Documents\\Files.exe" wide //weight: 1
        $x_1_5 = "\\Live Screen Saver.scr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

