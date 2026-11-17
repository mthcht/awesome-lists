rule Trojan_Win64_SeroRAT_PA_2147971451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SeroRAT.PA!MTB"
        threat_id = "2147971451"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SeroRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "SeroRAT" wide //weight: 4
        $x_1_2 = "/index.html" wide //weight: 1
        $x_1_3 = "sc delete WinDefSvc >nul 2>&1" wide //weight: 1
        $x_1_4 = "netsh advfirewall firewall delete rule name=\"BlkDoT\" >nul 2>&1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SeroRAT_A_2147982193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SeroRAT.A!MTB"
        threat_id = "2147982193"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SeroRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Local\\%s_hk_%lu" ascii //weight: 1
        $x_1_2 = "AMSI bypass: scan blocked for '%s' len=%lu from %s" ascii //weight: 1
        $x_1_3 = "Hiding registry value: '%s' (PID=%lu)" ascii //weight: 1
        $x_1_4 = "Hiding HWND %p (PID=%lu) [9p] from %s" ascii //weight: 1
        $x_1_5 = "NtDeleteKey: blocked deletion of hidden key from %s" ascii //weight: 1
        $x_1_6 = "Hiding TCP4 module: local=%u remote=%u pid=%lu from %s" ascii //weight: 1
        $x_1_7 = "AmsiHookThread: AmsiScanBuffer already hooked fn=%p tramp=%p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

