rule Trojan_Win64_OverlordRat_CAT_2147975793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRat.CAT!MTB"
        threat_id = "2147975793"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "overlord-client" ascii //weight: 5
        $x_5_2 = "readClipboardText" ascii //weight: 5
        $x_5_3 = "CheckInstalledBrowsers" ascii //weight: 5
        $x_5_4 = "CaptureAndSend" ascii //weight: 5
        $x_5_5 = "keylogger.go" ascii //weight: 5
        $x_5_6 = "persistence.go" ascii //weight: 5
        $x_5_7 = "screenshot.go" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OverlordRat_LR_2147976896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverlordRat.LR!MTB"
        threat_id = "2147976896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverlordRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {44 0f b6 84 04 bf 00 00 00 45 89 c1 41 c1 e9 04 45 0f b6 0c 09 44 88 4c 42 fe 41 83 e0 0f 45 0f b6 04 08 44 88 44 42 ff 44 0f b6 84 04 c0 00 00 00 45 89 c1 41 c1 e9 04 45 0f b6 0c 09 44 88 0c 42 41 83 e0 0f 45 0f b6 04 08 44 88 44 42 01 48 83 c0 02 48 83 f8 21}  //weight: 20, accuracy: High
        $x_1_2 = "pe_load: LdrLoadDll(\"%s\") failed - aborting load" ascii //weight: 1
        $x_2_3 = "[ws] upgrade rejected (HTTP %lu)" ascii //weight: 2
        $x_3_4 = "OverlordBeacon/1.0" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

