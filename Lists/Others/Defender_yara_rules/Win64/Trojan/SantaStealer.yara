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

