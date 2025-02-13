rule VirTool_Win64_Soushelesz_A_2147898255_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Soushelesz.A!MTB"
        threat_id = "2147898255"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Soushelesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".buildplaylist" ascii //weight: 1
        $x_1_2 = ".encodeCommand" ascii //weight: 1
        $x_1_3 = "github.com/zmb3/spotify" ascii //weight: 1
        $x_1_4 = ".socksAuthMethod" ascii //weight: 1
        $x_1_5 = "net/http.persistConnWriter.Write" ascii //weight: 1
        $x_1_6 = "AddConn" ascii //weight: 1
        $x_1_7 = "RemoteAddr" ascii //weight: 1
        $x_1_8 = "AddTracksToPlaylist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

