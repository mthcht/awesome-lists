rule Trojan_Win32_TrickbotVP_A_2147766723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TrickbotVP.A!MTB"
        threat_id = "2147766723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TrickbotVP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vpnDll build %s %s started" ascii //weight: 1
        $x_1_2 = "VPN bridge failure" ascii //weight: 1
        $x_1_3 = "11:43" ascii //weight: 1
        $x_1_4 = "vpnDll.dll" ascii //weight: 1
        $x_1_5 = "WantRelease" ascii //weight: 1
        $x_1_6 = "RasGetConnectStatusA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

