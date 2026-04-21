rule Trojan_Win64_AgentB_AHA_2147966523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentB.AHA!MTB"
        threat_id = "2147966523"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {44 0f b6 42 fc 44 09 c0 44 0f b6 42 ff 41 c1 e0 ?? 44 09 c0 89 84 0c d0 00 00 00 48 83 c1 ?? 48 83 f9 ?? 75}  //weight: 30, accuracy: Low
        $x_20_2 = {41 89 ca 88 4a fc 88 6a fd 41 c1 ea ?? c1 e9 ?? 44 88 52 fe 88 4a ff 49 83 f9 ?? 75}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AgentB_AHB_2147966719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentB.AHB!MTB"
        threat_id = "2147966719"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {84 24 40 01 00 00 66 90 0f b6 50 ?? 48 83 c0 ?? 48 83 c1 ?? 83 f2 ?? 88 51 ff 48 39 c6 75}  //weight: 20, accuracy: Low
        $x_30_2 = {48 89 78 10 48 bf 69 6e 6a 65 63 74 69 6f 48 89 68 18 48 bd 6e 20 73 75 63 63 65 73}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AgentB_AHC_2147966743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentB.AHC!MTB"
        threat_id = "2147966743"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "[DataSender] TelegramSender::SendFile returned:" ascii //weight: 20
        $x_10_2 = "[Startup] Failed to add to startup" ascii //weight: 10
        $x_30_3 = "\\Packages\\38053Unigram.Unigram_8wekyb3d8bbwe\\LocalState\\tdata" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_AgentB_AGB_2147967434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AgentB.AGB!MTB"
        threat_id = "2147967434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {29 d1 d3 f8 89 d1 41 d3 e6 44 09 f0 43 32 04 0a 83 f0 ?? 43 88 04 0a 49 ff c1 45 39 cb}  //weight: 5, accuracy: Low
        $x_5_2 = {31 c9 3b 4c 24 78 89 c8 ?? ?? 31 d2 f7 f6 8d 42 01 41 8a 04 07 41 30 44 0d 00 48 ff c1 eb e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

