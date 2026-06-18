rule Trojan_MacOS_Overlord_A_2147971885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Overlord.A!AMTB"
        threat_id = "2147971885"
        type = "Trojan"
        platform = "MacOS: "
        family = "Overlord"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sync/atomic.(*Pointer[go.shape.struct { ServerURLs []string; ServerIndex int; RawServerListURL string; Mutex string;" ascii //weight: 1
        $x_1_2 = "Country string; OS string; Arch string; Version string; AgentToken string; CaptureInterval time.Duration;" ascii //weight: 1
        $x_1_3 = "TLSInsecureSkipVerify bool; TLSCAPath string; TLSClientCert string; TLSClientKey string }]).Store" ascii //weight: 1
        $x_1_4 = "TLSInsecureSkipVerify bool; TLSCAPath string; TLSClientCert string; TLSClientKey string }]).Load" ascii //weight: 1
        $x_1_5 = "main.walletCfgSnapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

