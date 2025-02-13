rule Trojan_MSIL_AntiVm_NA_2147906969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AntiVm.NA!MTB"
        threat_id = "2147906969"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 02 07 6f 7c 00 00 0a 03 07 6f 7c 00 00 0a 61 60 0a 07 17 58 0b 07 02 6f 15 00 00 0a 32 e1}  //weight: 10, accuracy: High
        $x_1_2 = "drivers\\vmmouse.sys" ascii //weight: 1
        $x_1_3 = "drivers\\vmhgfs.sys" ascii //weight: 1
        $x_1_4 = "taskkill /f /im OllyDbg.exe" ascii //weight: 1
        $x_1_5 = "sc stop wireshark" ascii //weight: 1
        $x_1_6 = "taskkill /f /im HTTPDebugger.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AntiVm_ND_2147928827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AntiVm.ND!MTB"
        threat_id = "2147928827"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntiVm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 2
        $x_1_2 = "VirtualBox" ascii //weight: 1
        $x_1_3 = "vmware" ascii //weight: 1
        $x_1_4 = "SbieDll.dll" ascii //weight: 1
        $x_1_5 = "Ergo_Wallet" ascii //weight: 1
        $x_1_6 = "Electrum" ascii //weight: 1
        $x_1_7 = "Bitcoin_Core" ascii //weight: 1
        $x_1_8 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_9 = "/c taskkill.exe /im chrome.exe /f" ascii //weight: 1
        $x_1_10 = "/c schtasks /create /f /sc onlogon /rl highest /tn" ascii //weight: 1
        $x_1_11 = "Google\\Chrome\\User Data\\Default\\Local Extension Settings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

