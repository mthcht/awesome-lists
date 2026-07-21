rule Trojan_Win32_TeleShim_GVA_2147974258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeleShim.GVA!MTB"
        threat_id = "2147974258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeleShim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 04 8b 5c 24 08 0f b6 1c 3b 89 fd 83 e5 0f 32 1c 28 88 1c 39 47 bb ?? ?? ?? ?? 83 ff 05 89 7c 24 10 89 7c 24 04 0f 44 de 89 1c 24 eb b5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TeleShim_GVB_2147974259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TeleShim.GVB!MTB"
        threat_id = "2147974259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TeleShim"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CVR9EEA.tmp" ascii //weight: 1
        $x_1_2 = "libjpeg-turbo" ascii //weight: 1
        $x_1_3 = "sendDocument?chat_id=" ascii //weight: 1
        $x_1_4 = "/getFile?file_id=" ascii //weight: 1
        $x_1_5 = "uploaded" ascii //weight: 1
        $x_1_6 = "sendMessage?chat_id=" ascii //weight: 1
        $x_1_7 = "file_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

