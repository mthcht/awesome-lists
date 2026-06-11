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

