rule TrojanProxy_Win64_Magroxy_A_2147847368_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win64/Magroxy.A!dha"
        threat_id = "2147847368"
        type = "TrojanProxy"
        platform = "Win64: Windows 64-bit platform"
        family = "Magroxy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%!PS-Adobe-" ascii //weight: 1
        $x_1_2 = "github.com/fatedier/frp/cmd/frpc" ascii //weight: 1
        $x_1_3 = "github.com/fatedier/frp/cmd/frpc/sub.startService" ascii //weight: 1
        $x_1_4 = "MAGA2024!!!" ascii //weight: 1
        $x_1_5 = "HTTP_PROXYHost: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

