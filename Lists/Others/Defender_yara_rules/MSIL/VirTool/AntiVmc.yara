rule VirTool_MSIL_AntiVmc_YE_2147741746_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AntiVmc.YE!MTB"
        threat_id = "2147741746"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVmc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "newstub.VmDetector" ascii //weight: 5
        $x_5_2 = "VirtualMachineDetector" ascii //weight: 5
        $x_1_3 = "F935DC21-1CF0-11D0-ADB9-00C04FD58A0B" ascii //weight: 1
        $x_1_4 = "24BE5A30-EDFE-11D2-B933-00104B365C9F" ascii //weight: 1
        $x_1_5 = "41904400-BE18-11D3-A28B-00104BD35090" ascii //weight: 1
        $x_1_6 = "newstub.IWshRuntimeLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_AntiVmc_YF_2147741747_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/AntiVmc.YF!MTB"
        threat_id = "2147741747"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVmc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\vmGuestLib.dll" wide //weight: 1
        $x_1_2 = "\\vboxmrxnp.dll" wide //weight: 1
        $x_1_3 = "SbieDll.dll" wide //weight: 1
        $x_1_4 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 [0-3] 20 00 2d 00 6e 00 20 00 [0-3] 20 00 26 00 20 00 64 00 65 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

