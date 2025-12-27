rule Trojan_Win64_Maranhao_GAS_2147952370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Maranhao.GAS!MTB"
        threat_id = "2147952370"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Maranhao"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "api.maranhaogang.fun" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Maranhao_GAU_2147952433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Maranhao.GAU!MTB"
        threat_id = "2147952433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Maranhao"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_7_1 = "\\\\.\\pipe\\ChromeDecryptIPC_" ascii //weight: 7
        $x_7_2 = "PAYLOAD_DLL" ascii //weight: 7
        $x_1_3 = "--disable-gpu" ascii //weight: 1
        $x_1_4 = "--no-sandbox" ascii //weight: 1
        $x_1_5 = "Google\\Chrome\\Application\\chrome" ascii //weight: 1
        $x_1_6 = "Microsoft\\Edge\\Application\\msedge" ascii //weight: 1
        $x_1_7 = "WriteVirtualMemory" ascii //weight: 1
        $x_1_8 = "AllocateVirtualMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_7_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Maranhao_GAV_2147952434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Maranhao.GAV!MTB"
        threat_id = "2147952434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Maranhao"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wyCgZs8VE" ascii //weight: 2
        $x_1_2 = "bKcHXT9bf" ascii //weight: 1
        $x_1_3 = "jPD9Y6NUr" ascii //weight: 1
        $x_1_4 = "luSa6nyrI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

