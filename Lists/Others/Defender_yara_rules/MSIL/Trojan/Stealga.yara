rule Trojan_MSIL_Stealga_DC_2147939989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealga.DC!MTB"
        threat_id = "2147939989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "160"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "api.telegram.org/bot" ascii //weight: 100
        $x_10_2 = "Decrypt" ascii //weight: 10
        $x_10_3 = "User Data\\Default\\Local Extension Settings" ascii //weight: 10
        $x_10_4 = "chat_id" ascii //weight: 10
        $x_10_5 = "chrome.exe" ascii //weight: 10
        $x_10_6 = "msedge.exe" ascii //weight: 10
        $x_10_7 = "brave.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealga_MDA_2147963860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealga.MDA!MTB"
        threat_id = "2147963860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealga"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 6f 89 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "base64EncodedData" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

