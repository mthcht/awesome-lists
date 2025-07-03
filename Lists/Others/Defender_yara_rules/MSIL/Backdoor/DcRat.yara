rule Backdoor_MSIL_DcRat_SM_2147945333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DcRat.SM!MTB"
        threat_id = "2147945333"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 07 09 58 91 02 7b 0b 00 00 04 09 91 fe 01 13 05 11 05 2d 05 00 16 0c 2b 16 00 09 17 58 0d 09 02 7b 0b 00 00 04 8e 69 fe 04 13 05 11 05 2d cf}  //weight: 2, accuracy: High
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii //weight: 2
        $x_2_3 = "ShowSuperHidden" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DcRat_SN_2147945334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DcRat.SN!MTB"
        threat_id = "2147945334"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$2f92f2f9-dfef-4259-bf2a-9db9ec5d855c" ascii //weight: 2
        $x_2_2 = "BXCJDF.Properties.Resources" ascii //weight: 2
        $x_2_3 = "BXCJDF.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

