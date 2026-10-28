rule Trojan_Win64_VitaminStealer_LR_2147981068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VitaminStealer.LR!MTB"
        threat_id = "2147981068"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VitaminStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Vitamin Stealer" ascii //weight: 2
        $x_3_2 = "passwordsHarvested" ascii //weight: 3
        $x_4_3 = "Seed Phrase:" ascii //weight: 4
        $x_5_4 = "fake_progress" ascii //weight: 5
        $x_6_5 = "passwordManagers" ascii //weight: 6
        $x_7_6 = "sync-state.dat" ascii //weight: 7
        $x_8_7 = "auditors_screenshot.jpg" ascii //weight: 8
        $x_9_8 = "browsing_history.txt" ascii //weight: 9
        $x_10_9 = "crypto_wallets.txt" ascii //weight: 10
        $x_11_10 = "wifi_profiles.txt" ascii //weight: 11
        $x_12_11 = "Wallets.txt" ascii //weight: 12
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_4_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_9_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_10_*) and 1 of ($x_9_*) and 1 of ($x_8_*))) or
            ((1 of ($x_11_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_11_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_11_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_4_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_5_*))) or
            ((1 of ($x_11_*) and 1 of ($x_8_*) and 1 of ($x_7_*) and 1 of ($x_6_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_7_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_8_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_6_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_7_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_8_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*) and 1 of ($x_9_*))) or
            ((1 of ($x_12_*) and 1 of ($x_6_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_7_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_6_*) and 1 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_8_*) and 1 of ($x_7_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_5_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_6_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_7_*))) or
            ((1 of ($x_12_*) and 1 of ($x_9_*) and 1 of ($x_8_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_6_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_7_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_8_*))) or
            ((1 of ($x_12_*) and 1 of ($x_10_*) and 1 of ($x_9_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*) and 1 of ($x_4_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*) and 1 of ($x_5_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*) and 1 of ($x_6_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*) and 1 of ($x_7_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*) and 1 of ($x_8_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*) and 1 of ($x_9_*))) or
            ((1 of ($x_12_*) and 1 of ($x_11_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

