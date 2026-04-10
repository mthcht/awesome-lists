rule Trojan_Win64_Xegumumune_SX_2147965831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xegumumune.SX!MTB"
        threat_id = "2147965831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xegumumune"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Kong\\Keylogger" ascii //weight: 30
        $x_10_2 = "Software\\Kong\\Client\\ClientVersion" ascii //weight: 10
        $x_5_3 = "[Local\\ClientMutex_%08X" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xegumumune_MK_2147966745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xegumumune.MK!MTB"
        threat_id = "2147966745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xegumumune"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {44 0f b6 c8 4c 8b c6 41 c1 e1 10 8b d5 49 83 c9 01 48 8b cf 49 8b c1 48 0d 00 00 00 c0 81 fd 01 01 00 00 4c 0f 44 c8 ff 15}  //weight: 20, accuracy: High
        $x_10_2 = "--no-sandbox --disable-gpu --user-data-dir=\"%s\\ch_h" ascii //weight: 10
        $x_5_3 = "[SYSTEM] Keylog Channel Active" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

