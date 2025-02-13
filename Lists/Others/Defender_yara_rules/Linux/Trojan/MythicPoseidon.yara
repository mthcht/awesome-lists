rule Trojan_Linux_MythicPoseidon_A_2147827589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MythicPoseidon.A"
        threat_id = "2147827589"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MythicPoseidon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 0f 11 7c 24 40 48 8d ?? ?? ?? ?? ?? bb 03 00 00 00 48 8b 4c 24 30 48 8b 7c 24 28 [0-5] e8 ?? ?? ?? ff 48 89 44 24 40 48 89 5c 24 48 48 85 c9 0f 85 ?? 00 00 00 48 89 44 24 40 48 89 5c 24 48 48 8b 8c 24 a8 01 00 00 48 8b 41 60 48 8d 5c 24 40 e8 ?? ?? ?? ff 48 8d ?? ?? ?? ?? ?? 48 89 8c 24 80 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {48 89 44 24 20 48 89 44 24 78 48 8b 4c 24 30 48 8b 49 38 48 8b 59 38 48 8b 7c 24 70 48 8b 4c 24 68 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ff 84 00}  //weight: 2, accuracy: Low
        $x_2_3 = {48 89 c2 31 c0 4c 8d ?? ?? ?? ?? ?? 41 b9 01 00 00 00 f0 45 0f b1 08 41 0f 94 c2 45 84 d2 75 ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ff 48 8b 4c 24 48 48 8b 54 24 50 48 8b 5c 24 40 4c 8d ?? ?? ?? ?? ?? 41 b9 01 00 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {48 83 ec 28 48 89 6c 24 20 48 8d ?? ?? ?? 48 89 44 24 30 48 89 7c 24 48 48 89 74 24 50 48 89 4c 24 40 48 8b 15 ?? ?? ?? ?? 49 89 c0 48 8d ?? ?? ?? ?? ?? 49 89 d9 48 89 d3 4c 89 c1 4c 89 cf}  //weight: 2, accuracy: Low
        $x_2_5 = {48 81 ec b8 02 00 00 48 89 ac 24 b0 02 00 00 48 8d ?? ?? ?? ?? ?? 00 44 0f 11 bc 24 a0 02 00 00 c6 44 24 2e 00 48 89 84 24 c0 02 00 00 48 89 9c 24 c8 02 00 00 48 89 8c 24 d0 02 00 00 48 89 bc 24 d8 02 00 00 f2 0f 11 84 24 e0 02 00 00 48 89 b4 24 e8 02 00 00 4c 89 84 24 f0 02 00 00 4c 89 8c 24 f8 02 00 00}  //weight: 2, accuracy: Low
        $x_2_6 = "github.com/MythicAgents" ascii //weight: 2
        $x_2_7 = "eUyoZAIGIbWz4JxUNxl2P1IMvubKMtkVcgO0xrV55bs" ascii //weight: 2
        $x_1_8 = "ID json:\"id\"" ascii //weight: 1
        $x_1_9 = "IP json:\"ip\"" ascii //weight: 1
        $x_1_10 = "json:\"url\"" ascii //weight: 1
        $x_1_11 = "htmlPostData" ascii //weight: 1
        $x_1_12 = "ScanPortRanges" ascii //weight: 1
        $x_1_13 = "ScreenshotData" ascii //weight: 1
        $x_1_14 = "SearchWithType" ascii //weight: 1
        $x_1_15 = "SetSleepJitter" ascii //weight: 1
        $x_1_16 = "GetFileFromMythic" ascii //weight: 1
        $x_1_17 = "SendFileToMythic" ascii //weight: 1
        $x_1_18 = "SetSleepInterval" ascii //weight: 1
        $x_1_19 = "upload.uploadArgs" ascii //weight: 1
        $x_1_20 = "keystate.EventType" ascii //weight: 1
        $x_1_21 = "keystate.KeyLogger" ascii //weight: 1
        $x_1_22 = "link_tcp.Arguments" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

