rule Trojan_Linux_ZinFoq_A_2147962231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ZinFoq.A!MTB"
        threat_id = "2147962231"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ZinFoq"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src/mode/httpAndTcp/shell/ShellLinux.Exec_shell" ascii //weight: 1
        $x_1_2 = "src/mode/process/ProcessLinux.sendBody" ascii //weight: 1
        $x_1_3 = "src/mode/utils.SendDataByPost" ascii //weight: 1
        $x_1_4 = "/httpAndTcp/shell/ShellLinux.Shell" ascii //weight: 1
        $x_1_5 = "/httpAndTcp/inForward.addTask" ascii //weight: 1
        $x_1_6 = "/httpAndTcp/socket5Quick.(*proxy).getAddrPort" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

