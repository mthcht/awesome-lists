rule Trojan_Win64_SantaStealer_LM_2147959245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SantaStealer.LM!MTB"
        threat_id = "2147959245"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b6 14 03 83 f2 01 88 14 01 48 83 c0 01 4c 39 c0 75 ?? 4d 63 c9 48 89 c8 42 c6 04 09 00 48 83 c4 20}  //weight: 20, accuracy: Low
        $x_15_2 = "t.me/SantaStealer" ascii //weight: 15
        $x_5_3 = "ChromeElevator_GetEncryptedBlob" ascii //weight: 5
        $x_3_4 = "ChromeElevator_Cleanup" ascii //weight: 3
        $x_2_5 = "cryptocurrency" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SantaStealer_A_2147959612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SantaStealer.A!AMTB"
        threat_id = "2147959612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SantaStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Stealer" ascii //weight: 2
        $x_2_2 = "31.57.38.244" ascii //weight: 2
        $x_2_3 = "80.76.49.114" ascii //weight: 2
        $x_1_4 = "BrowserSummary.txt" ascii //weight: 1
        $x_1_5 = "Download History" ascii //weight: 1
        $x_1_6 = "config\\loginusers" ascii //weight: 1
        $x_1_7 = "Chrome|User Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

