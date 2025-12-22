rule HackTool_Win64_Injector_PAHB_2147959939_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Injector.PAHB!MTB"
        threat_id = "2147959939"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\IAmAntimalware.pdb" ascii //weight: 5
        $x_1_2 = "launchProtected" ascii //weight: 1
        $x_1_3 = "certData" ascii //weight: 1
        $x_2_4 = "CertAddCertificateContextToStore" ascii //weight: 2
        $x_1_5 = "sidInfo" ascii //weight: 1
        $x_1_6 = "sourceKeyPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

