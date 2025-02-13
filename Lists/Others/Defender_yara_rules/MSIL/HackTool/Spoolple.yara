rule HackTool_MSIL_Spoolple_2147766868_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Spoolple"
        threat_id = "2147766868"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spoolple"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Converted DLL to shellcode" wide //weight: 1
        $x_1_2 = "[+] Executing RDI" wide //weight: 1
        $x_1_3 = "SpoolSample.exe" wide //weight: 1
        $x_1_4 = "TARGET CAPTURESERVER" wide //weight: 1
        $x_1_5 = "File is not a DLL, Exiting." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

