rule HackTool_Linux_Fscan_A_2147917119_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Fscan.A!MTB"
        threat_id = "2147917119"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Fscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shadow1ng/fscan" ascii //weight: 1
        $x_1_2 = "Plugins.exploit" ascii //weight: 1
        $x_1_3 = "exploit-db" ascii //weight: 1
        $x_1_4 = "hackgov" ascii //weight: 1
        $x_1_5 = "Plugins.Brutelist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Linux_Fscan_B_2147940625_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Fscan.B!MTB"
        threat_id = "2147940625"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Fscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetHostCrackIps" ascii //weight: 2
        $x_2_2 = "GetPwdCrackTabData" ascii //weight: 2
        $x_2_3 = "GetCyberTabData" ascii //weight: 2
        $x_1_4 = "TargetWebScanForFingerAndPoc" ascii //weight: 1
        $x_1_5 = "PwdCrackScan" ascii //weight: 1
        $x_1_6 = "nucleiserveraccessdeviceroutercameraNuclei" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

