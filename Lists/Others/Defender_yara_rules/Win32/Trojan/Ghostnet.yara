rule Trojan_Win32_Ghostnet_SA_2147733580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghostnet.SA!MTB"
        threat_id = "2147733580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghostnet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 75 f0 e8 30 00 8a ?? 32 ?? 02 ?? 88 ?? 83 ?? 01 83 ?? 01 75 f0}  //weight: 1, accuracy: Low
        $x_1_2 = "NoDrives" ascii //weight: 1
        $x_1_3 = "RestrictRun" ascii //weight: 1
        $x_1_4 = "NoNetConnectDisconnect" ascii //weight: 1
        $x_1_5 = "NoRecentDocsHistory" ascii //weight: 1
        $x_1_6 = "NoClose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

