rule HackTool_MSIL_AutoKms_2147711767_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/AutoKms"
        threat_id = "2147711767"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AutoKms"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&echo Activating Microsoft software products for FREE&echo" ascii //weight: 2
        $x_2_2 = "if %i%==1 set KMS_Sev=" ascii //weight: 2
        $x_2_3 = "cscript //nologo c:\\windows\\system32\\slmgr.vbs" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule HackTool_MSIL_AutoKms_PA2_2147899466_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/AutoKms.PA2!MTB"
        threat_id = "2147899466"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AutoKms"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "progvirus@gmail.com" ascii //weight: 1
        $x_1_2 = "!!a7aprog!!" ascii //weight: 1
        $x_1_3 = "How To Hack E-Mail" ascii //weight: 1
        $x_1_4 = "ShutdownMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

