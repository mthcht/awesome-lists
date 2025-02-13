rule VirTool_Win64_Myrddin_E_2147895387_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Myrddin.E!MTB"
        threat_id = "2147895387"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Myrddin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").RemoteAddr" ascii //weight: 1
        $x_1_2 = ").Hostname" ascii //weight: 1
        $x_1_3 = ").Password" ascii //weight: 1
        $x_1_4 = "net/http.persistConnWriter.Write" ascii //weight: 1
        $x_1_5 = ").GetSessionTicket" ascii //weight: 1
        $x_1_6 = ").AddConn" ascii //weight: 1
        $x_1_7 = ").NewSession" ascii //weight: 1
        $x_1_8 = ").Server" ascii //weight: 1
        $x_1_9 = ").RemoteSock" ascii //weight: 1
        $x_1_10 = "AgentInfo" ascii //weight: 1
        $x_1_11 = "github.com/Ne0nd0g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Myrddin_F_2147900127_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Myrddin.F!MTB"
        threat_id = "2147900127"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Myrddin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").RemoteAddr" ascii //weight: 1
        $x_1_2 = ").Hostname" ascii //weight: 1
        $x_1_3 = ").Password" ascii //weight: 1
        $x_1_4 = "SetSessionTicket" ascii //weight: 1
        $x_1_5 = "addConn" ascii //weight: 1
        $x_1_6 = ").NewSession" ascii //weight: 1
        $x_1_7 = ").Server" ascii //weight: 1
        $x_1_8 = ").RemoteSock" ascii //weight: 1
        $x_1_9 = "AgentInfo" ascii //weight: 1
        $x_1_10 = ".ClientConn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

