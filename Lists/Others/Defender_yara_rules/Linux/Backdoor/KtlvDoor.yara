rule Backdoor_Linux_KtlvDoor_A_2147940019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/KtlvDoor.A!MTB"
        threat_id = "2147940019"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "KtlvDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tools/cmd/acc/agent_acc/handler/portscan/template.ScanFuncRegister" ascii //weight: 1
        $x_1_2 = "/agent_acc/conf.getMachineFeature.func" ascii //weight: 1
        $x_1_3 = "/agent_acc/conf.UpdateHostInfo.func" ascii //weight: 1
        $x_1_4 = "/JKme/go-ntlmssp.ChallengeMsg.TargetInfo" ascii //weight: 1
        $x_1_5 = "/handler/portscan/ps_plugins.ScanWeb.func" ascii //weight: 1
        $x_1_6 = "tools/internal/utils/shellquote.glob..func" ascii //weight: 1
        $x_1_7 = "tools/pkg/crypto.Xor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

