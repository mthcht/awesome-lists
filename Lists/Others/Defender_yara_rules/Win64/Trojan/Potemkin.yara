rule Trojan_Win64_Potemkin_AUWB_2147971821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Potemkin.AUWB!MTB"
        threat_id = "2147971821"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Potemkin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Transfer-Encoding" ascii //weight: 1
        $x_1_2 = "Proxy-Authorization" ascii //weight: 1
        $x_1_3 = "Content-Encoding" ascii //weight: 1
        $x_1_4 = "User-Agent" ascii //weight: 1
        $x_1_5 = "Connection established" ascii //weight: 1
        $x_1_6 = "[DNS] FOUND domain" ascii //weight: 1
        $x_1_7 = "[DNS] exhausted all" ascii //weight: 1
        $x_5_8 = "\\hyper-v.ver" ascii //weight: 5
        $x_1_9 = "os_info" ascii //weight: 1
        $x_1_10 = "/api/client/verify" ascii //weight: 1
        $x_1_11 = "[Chan] verify status=" ascii //weight: 1
        $x_5_12 = "[Chan] POST" ascii //weight: 5
        $x_1_13 = "/tasks/collect" ascii //weight: 1
        $x_1_14 = "[DLL] GET" ascii //weight: 1
        $x_1_15 = "[Agent] DNS lookup seed=" ascii //weight: 1
        $x_5_16 = "[Agent] DNS: no domain found, sleeping" ascii //weight: 5
        $x_1_17 = "[Agent] poll got_task=" ascii //weight: 1
        $x_5_18 = "[Agent] LoadAndRunDLL=" ascii //weight: 5
        $x_1_19 = "[Agent] DLL returned (updatedll), reloading" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

