rule Trojan_Win32_Miner_M_2147821695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miner.M!MTB"
        threat_id = "2147821695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Prodigy B0T" wide //weight: 1
        $x_1_2 = "Bot.vbp" wide //weight: 1
        $x_1_3 = "ProxyServer" wide //weight: 1
        $x_1_4 = "-list_devices true -f dshow -i dummy" wide //weight: 1
        $x_1_5 = "taskkill /F /IM chrome.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

