rule Trojan_Win64_karstorat_ARK_2147965096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/karstorat.ARK!MTB"
        threat_id = "2147965096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "karstorat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ROTATE_ON" ascii //weight: 1
        $x_1_2 = "ROTATE_OFF" ascii //weight: 1
        $x_1_3 = "MOUSE_SWAP" ascii //weight: 1
        $x_1_4 = "MOUSE_RESTORE" ascii //weight: 1
        $x_1_5 = "CLIPBOARD_ON" ascii //weight: 1
        $x_1_6 = "CLIPBOARD_OFF" ascii //weight: 1
        $x_1_7 = "SELF_DESTRUCT" ascii //weight: 1
        $x_1_8 = "UAC_BYPASS" ascii //weight: 1
        $x_1_9 = "DOWNLOAD_RUN" ascii //weight: 1
        $x_1_10 = "capCreateCaptureWindowA" ascii //weight: 1
        $x_5_11 = "212.227.65.132" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

