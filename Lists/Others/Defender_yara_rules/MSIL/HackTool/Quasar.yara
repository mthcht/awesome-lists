rule HackTool_MSIL_Quasar_SN_2147969410_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Quasar.SN!MTB"
        threat_id = "2147969410"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://dynupdate.no-ip.com/nic/update?hostname={0}" wide //weight: 2
        $x_2_2 = "KEEP THIS FILE SAFE! LOSS RESULTS IN LOOSING ALL CLIENTS!" wide //weight: 2
        $x_2_3 = "Please backup the certificate now. Loss of the certificate results in loosing all clients!" wide //weight: 2
        $x_2_4 = "https://github.com/Onimai/Onimai" wide //weight: 2
        $x_2_5 = "Onimai.Server.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

