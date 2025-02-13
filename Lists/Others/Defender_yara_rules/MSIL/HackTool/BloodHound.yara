rule HackTool_MSIL_BloodHound_SA_2147741581_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/BloodHound.SA"
        threat_id = "2147741581"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BloodHound"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "BloodHound.bin" wide //weight: 5
        $x_3_2 = "costura.commandline.dll.compressed" ascii //weight: 3
        $x_3_3 = "costura.heijden.dns.dll.compressed" ascii //weight: 3
        $x_1_4 = "SamServerExecute" wide //weight: 1
        $x_1_5 = "EncryptedTextPwdAllowed" ascii //weight: 1
        $x_1_6 = "get_AccountDomainSid" ascii //weight: 1
        $x_1_7 = "get_ComputerSamAccountName" ascii //weight: 1
        $x_1_8 = "SetSecurityDescriptorBinaryForm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

