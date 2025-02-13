rule VirTool_Win32_Myrddin_D_2147812764_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Myrddin.D"
        threat_id = "2147812764"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Myrddin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").SendMerlinMessage" ascii //weight: 1
        $x_1_2 = "net/http.persistConnWriter.Write" ascii //weight: 1
        $x_1_3 = "github.com/lucas-clemente" ascii //weight: 1
        $x_1_4 = "github.com/marten-seemann" ascii //weight: 1
        $x_1_5 = ").NewSession" ascii //weight: 1
        $x_1_6 = ").RemoteAddr" ascii //weight: 1
        $x_1_7 = ").AddConn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Myrddin_D_2147812764_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Myrddin.D"
        threat_id = "2147812764"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Myrddin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net/http.persistConnWriter.Write" ascii //weight: 1
        $x_1_2 = ").NewSession" ascii //weight: 1
        $x_1_3 = ").RemoteAddr" ascii //weight: 1
        $x_1_4 = ").AddConn" ascii //weight: 1
        $x_1_5 = ").Hostname" ascii //weight: 1
        $x_1_6 = ").Password" ascii //weight: 1
        $x_1_7 = ".ClientTaskResponse" ascii //weight: 1
        $x_1_8 = ".ServerPostResponse" ascii //weight: 1
        $x_1_9 = ".clientSessionState" ascii //weight: 1
        $x_1_10 = ").GetSessionTicket" ascii //weight: 1
        $x_1_11 = "AgentInfo)" ascii //weight: 1
        $x_1_12 = ".ServerTaskResponse" ascii //weight: 1
        $x_1_13 = ").SessionTicket" ascii //weight: 1
        $x_1_14 = ").SetSessionState" ascii //weight: 1
        $x_1_15 = ").RemoteSock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

