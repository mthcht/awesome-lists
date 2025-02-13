rule HackTool_MSIL_Kmscl_A_2147740414_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Kmscl.A!ibt"
        threat_id = "2147740414"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kmscl"
        severity = "High"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Waiting sppsvc close" wide //weight: 1
        $x_1_2 = "KMS Client" wide //weight: 1
        $x_1_3 = "qemu-img.exe" wide //weight: 1
        $x_1_4 = "Taskkill.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

