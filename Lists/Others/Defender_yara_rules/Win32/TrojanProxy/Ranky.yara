rule TrojanProxy_Win32_Ranky_B_2147803478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Ranky.gen!B"
        threat_id = "2147803478"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranky"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Advanced DHTML Enable" ascii //weight: 1
        $x_1_2 = "HTTP/1.0 200 Connection established" ascii //weight: 1
        $x_1_3 = "HTTP/1.0 201 Unable to connect" ascii //weight: 1
        $x_10_4 = {f2 ae f7 d1 49 51 8d 4c 24 ?? 51 52 e8 ?? ?? ?? ?? 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 83 c4 10 68 a0 bb 0d 00 ff d6 e9}  //weight: 10, accuracy: Low
        $x_10_5 = {99 b9 fd fb 00 00 f7 f9 81 c2 01 04 00 00 66 89 15 ?? ?? ?? ?? 68 e8 03 00 00 ff d6 33 d2 66 8b 15 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 85 c0 75 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanProxy_Win32_Ranky_2147803767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Ranky"
        threat_id = "2147803767"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {99 b9 fd fb 00 00 f7 f9 81 c2 01 04 00 00}  //weight: 4, accuracy: High
        $x_4_2 = {99 b9 40 9c 00 00 f7 f9 81 c2 10 27 00 00}  //weight: 4, accuracy: High
        $x_4_3 = {0f b7 c0 bf fe fb 00 00 be 00 04 00 00 99 8b cf f7 f9 03 d6}  //weight: 4, accuracy: High
        $x_4_4 = {99 b9 40 9c 00 00 8b 1d ?? ?? 40 00 f7 f9 66 c7 44 24 ?? 02 00 81 c2 10 27 00 00 52}  //weight: 4, accuracy: Low
        $x_3_5 = {ff fe ff 83 f8 68 75 ?? 0f b6 8d df ff fe ff 83 f9 70 75}  //weight: 3, accuracy: Low
        $x_3_6 = {80 bd 88 f2 ff ff 05 75 2f c6 85 88 f2 ff ff 05 88 9d 89 f2 ff ff}  //weight: 3, accuracy: High
        $x_3_7 = {80 bd 88 f2 ff ff 04 0f 85 da 03 00 00 8a 85 8a f2 ff ff}  //weight: 3, accuracy: High
        $x_2_8 = {73 68 65 64 0d 0a 50 72 6f 78 79 2d 61 67 65 6e}  //weight: 2, accuracy: High
        $x_2_9 = {00 00 68 b8 0b 00 00 8d 85 8c ?? ff ff 50}  //weight: 2, accuracy: Low
        $x_2_10 = {80 bd 8c f2 ff ff 47 74 0d 80 bd 8c f2 ff ff 50}  //weight: 2, accuracy: High
        $x_2_11 = {8b 85 80 f1 ff ff 25 ff 00 00 00 83 f8 47 74 15}  //weight: 2, accuracy: High
        $x_2_12 = {eb 13 68 20 4e 00 00 ff 76 08 e8 ?? ?? 00 00 85 c0 7d 08 6a 05}  //weight: 2, accuracy: Low
        $x_2_13 = {0f b6 8d d8 ff fe ff 83 f9 47 0f 85}  //weight: 2, accuracy: High
        $x_2_14 = {80 bd 88 f2 ff ff 47 74 0d 80 bd 88 f2 ff ff 50}  //weight: 2, accuracy: High
        $x_2_15 = {8d 7e 28 66 c7 07 02 00 e8 ?? ?? 00 00 6a 10 57 ff 76 08 66 89 46 2a e8 ?? ?? 00 00 85 c0}  //weight: 2, accuracy: Low
        $x_2_16 = {88 18 59 53 53 53 53 53 53 53 6a ff 6a 04 6a ff 57 ff 15}  //weight: 2, accuracy: High
        $x_2_17 = {40 00 3d b7 00 00 00 0f 84 ?? ?? 00 00 57 6a 01}  //weight: 2, accuracy: Low
        $x_2_18 = {56 56 56 56 56 56 56 6a ff 6a 02 6a ff 53 ff 15}  //weight: 2, accuracy: High
        $x_2_19 = {83 bd 6c ff ff ff 05 0f 82 97 00 00 00 83 bd 70 ff ff ff 01}  //weight: 2, accuracy: High
        $x_2_20 = {2f 61 2e 70 68 70 3f [0-4] 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_1_21 = {8d 45 fc 50 68 7e 66 04 80}  //weight: 1, accuracy: High
        $x_1_22 = {83 66 10 00 6a 11 6a 02 6a 02 e8}  //weight: 1, accuracy: High
        $x_1_23 = {8d 44 24 10 bb 06 00 02 00 50 53 6a 00 bf 02 00 00 80 68}  //weight: 1, accuracy: High
        $x_1_24 = "HTTP/1.0 200 Connection established" ascii //weight: 1
        $x_1_25 = "registerserviceprocess" ascii //weight: 1
        $x_1_26 = "Proxy-agent:" ascii //weight: 1
        $x_1_27 = "%d.%d.%d.%d" ascii //weight: 1
        $x_1_28 = "AutoUpdateMgr" ascii //weight: 1
        $x_1_29 = "/a.php?" ascii //weight: 1
        $x_1_30 = "/b.php?" ascii //weight: 1
        $x_1_31 = "%s:*:Enabled:%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

