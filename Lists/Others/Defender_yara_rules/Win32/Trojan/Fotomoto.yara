rule Trojan_Win32_Fotomoto_A_2147593504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fotomoto.gen!A"
        threat_id = "2147593504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fotomoto"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {26 00 6b 00 65 00 79 00 69 00 64 00 3d 00 00 00 26 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 00 00 26 00 75 00 73 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 3f 00 61 00 66 00 69 00 64 00 3d 00}  //weight: 3, accuracy: High
        $x_1_2 = "http://23.244.141.185/cgi-bin" wide //weight: 1
        $x_1_3 = "http://www.thedomaindata.com/" wide //weight: 1
        $x_3_4 = "DDC_Stop_Event" wide //weight: 3
        $x_3_5 = "%TEMP%\\aupddc.exe" wide //weight: 3
        $x_3_6 = "ezula_deniedsites" wide //weight: 3
        $x_3_7 = "ezula_dictionary" wide //weight: 3
        $x_3_8 = "ezula_enabled" wide //weight: 3
        $x_3_9 = "ezula_maxdup" wide //weight: 3
        $x_3_10 = "ezula_maxhilight" wide //weight: 3
        $x_3_11 = "internal_affiliate_id" wide //weight: 3
        $x_3_12 = "last_ezula_update_ID" wide //weight: 3
        $x_3_13 = "last_ezulasync" wide //weight: 3
        $x_3_14 = "mt_mediatraffic_enabled" wide //weight: 3
        $x_3_15 = "mt_popup_counter_notify" wide //weight: 3
        $x_3_16 = "next_fixed_ctx_popup_time" wide //weight: 3
        $x_3_17 = "next_mt_popup_time" wide //weight: 3
        $x_3_18 = "random_context_blacklist" wide //weight: 3
        $x_3_19 = "related_popups_enabled" wide //weight: 3
        $x_3_20 = {81 ec 20 02 00 00 56 68 c0 90 41 00 68 fc cb 41 00 e8 ba fc ff ff 83 c4 08 68 88 90 41 00 68 fc cb 41 00 e8 a8 fc ff ff 83 c4 08 ff 15 d8 50 41 00 68 80 90 41 00 68 fc cb 41 00 8b f0 e8 8e fc ff ff 68 68 90 41 00 56 e8 95 7a 00 00 83 c4 10 85 c0 0f 84 b8 00 00 00 68 2c 90 41 00 68 fc cb 41 00 e8 69 fc ff ff 68 98 8c 41 00 e8 4f 4f 00 00 83 c4 0c 68 f4 8f 41 00 68 fc cb 41 00 e8 4d fc ff ff 8d 44 24 0c c7 44 24 0c 00 00 00 00 50 c7 44 24 14 00 00 00 00 e8 69 79 00 00 83 c4 0c 68 b8 8f 41 00 68 fc cb 41 00 e8 21 fc ff ff 8b 35 f4 50 41 00 83 c4 08 68 98 8c 41 00 e8 2e 4d 00 00 83 c4 04 84 c0 74 29 8d 4c 24 08 51 e8 33 79 00 00 8b 54 24 0c 8b 4c 24 08 2b d1 83 c4 04 83 fa 1e 0f 8f b7 01 00 00 68 f4 01 00 00 ff d6 eb c6}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((18 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fotomoto_A_17832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fotomoto.A"
        threat_id = "17832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fotomoto"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 10
        $x_10_2 = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Windows File Protection" wide //weight: 10
        $x_10_3 = "DDC_Instance_Evnt" wide //weight: 10
        $x_1_4 = "http://23.244.141.185/cgi-bin" wide //weight: 1
        $x_1_5 = "%TEMP%\\aupddc.exe" wide //weight: 1
        $x_1_6 = "SFCDisable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fotomoto_A_17832_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fotomoto.A"
        threat_id = "17832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fotomoto"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "54"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {26 00 6b 00 65 00 79 00 69 00 64 00 3d 00 00 00 26 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 00 00 26 00 75 00 73 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 3f 00 61 00 66 00 69 00 64 00 3d 00}  //weight: 3, accuracy: High
        $x_1_2 = "http://23.244.141.185/cgi-bin" wide //weight: 1
        $x_1_3 = "http://www.thedomaindata.com/" wide //weight: 1
        $x_3_4 = "DDC_Stop_Event" wide //weight: 3
        $x_3_5 = "%TEMP%\\aupddc.exe" wide //weight: 3
        $x_3_6 = "ezula_deniedsites" wide //weight: 3
        $x_3_7 = "ezula_dictionary" wide //weight: 3
        $x_3_8 = "ezula_enabled" wide //weight: 3
        $x_3_9 = "ezula_maxdup" wide //weight: 3
        $x_3_10 = "ezula_maxhilight" wide //weight: 3
        $x_3_11 = "internal_affiliate_id" wide //weight: 3
        $x_3_12 = "last_ezula_update_ID" wide //weight: 3
        $x_3_13 = "last_ezulasync" wide //weight: 3
        $x_3_14 = "mt_mediatraffic_enabled" wide //weight: 3
        $x_3_15 = "mt_popup_counter_notify" wide //weight: 3
        $x_3_16 = "next_fixed_ctx_popup_time" wide //weight: 3
        $x_3_17 = "next_mt_popup_time" wide //weight: 3
        $x_3_18 = "random_context_blacklist" wide //weight: 3
        $x_3_19 = "related_popups_enabled" wide //weight: 3
        $x_3_20 = {81 ec 20 02 00 00 56 68 c0 90 41 00 68 fc cb 41 00 e8 ba fc ff ff 83 c4 08 68 88 90 41 00 68 fc cb 41 00 e8 a8 fc ff ff 83 c4 08 ff 15 d8 50 41 00 68 80 90 41 00 68 fc cb 41 00 8b f0 e8 8e fc ff ff 68 68 90 41 00 56 e8 95 7a 00 00 83 c4 10 85 c0 0f 84 b8 00 00 00 68 2c 90 41 00 68 fc cb 41 00 e8 69 fc ff ff 68 98 8c 41 00 e8 4f 4f 00 00 83 c4 0c 68 f4 8f 41 00 68 fc cb 41 00 e8 4d fc ff ff 8d 44 24 0c c7 44 24 0c 00 00 00 00 50 c7 44 24 14 00 00 00 00 e8 69 79 00 00 83 c4 0c 68 b8 8f 41 00 68 fc cb 41 00 e8 21 fc ff ff 8b 35 f4 50 41 00 83 c4 08 68 98 8c 41 00 e8 2e 4d 00 00 83 c4 04 84 c0 74 29 8d 4c 24 08 51 e8 33 79 00 00 8b 54 24 0c 8b 4c 24 08 2b d1 83 c4 04 83 fa 1e 0f 8f b7 01 00 00 68 f4 01 00 00 ff d6 eb c6}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((18 of ($x_3_*))) or
            (all of ($x*))
        )
}

