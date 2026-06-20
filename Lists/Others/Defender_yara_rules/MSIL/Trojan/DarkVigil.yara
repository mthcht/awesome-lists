rule Trojan_MSIL_DarkVigil_AHB_2147972000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkVigil.AHB!MTB"
        threat_id = "2147972000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkVigil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "KClient.DmtpFrame.Connection.FileTransferPlugin+<OnDmtpFileTransferring>d__" ascii //weight: 30
        $x_20_2 = "DClient.DmtpFrame.Helper.NoVpnHttpClientHelper+<LoopMessageAsync>d__" ascii //weight: 20
        $x_10_3 = "EClient.DmtpFrame.Connection.SystemEventsPlugin+<OnDmtpHandshaked>d__" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

