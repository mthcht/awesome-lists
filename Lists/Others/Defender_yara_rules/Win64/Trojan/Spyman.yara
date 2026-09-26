rule Trojan_Win64_Spyman_C_2147978910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Spyman.C!MTB"
        threat_id = "2147978910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Spyman"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "chrome-injector" ascii //weight: 1
        $x_1_2 = "Chrome-App-Bound-Encryption" ascii //weight: 1
        $x_1_3 = "start_webcam" ascii //weight: 1
        $x_1_4 = "start_keylogger" ascii //weight: 1
        $x_1_5 = "ransomware_decrypt" ascii //weight: 1
        $x_1_6 = "list_browsers" ascii //weight: 1
        $x_1_7 = "steal_browser" ascii //weight: 1
        $x_1_8 = "start_clipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

