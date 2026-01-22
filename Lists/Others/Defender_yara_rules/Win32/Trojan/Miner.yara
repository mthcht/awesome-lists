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

rule Trojan_Win32_Miner_LM_2147961624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miner.LM!MTB"
        threat_id = "2147961624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {72 98 35 00 70 28 65 01 00 0a 74 be 00 00 01 25 72 e0 34 00 70 6f 66 01 00 0a 25 20 10 27 00 00 6f 67 01 00 0a 6f 68 01 00 0a 0b 07 6f 69 01 00 0a 0c 28 35 01 00 0a 72 e6 35 00 70 28 27 00 00 0a 28 49 01 00 0a 2c 14 28 35 01 00 0a 72 e6 35 00 70 28 27 00 00 0a 28 6a 01 00 0a 28 35 01 00 0a 72 e6 35 00 70 28 27 00 00 0a}  //weight: 20, accuracy: High
        $x_10_2 = {72 98 34 00 70 28 65 01 00 0a 74 be 00 00 01 25 72 e0 34 00 70 6f 66 01 00 0a 25 20 10 27 00 00 6f 67 01 00 0a 6f 68 01 00 0a 0b 07 6f 69 01 00 0a 0c 28 35 01 00 0a 72 e8 34 00 70 28 27 00 00 0a 28 49 01 00 0a 2c 14 28 35 01 00 0a 72 e8 34 00 70 28 27 00 00 0a 28 6a 01 00 0a 28 35 01 00 0a 72 e8 34 00 70}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

