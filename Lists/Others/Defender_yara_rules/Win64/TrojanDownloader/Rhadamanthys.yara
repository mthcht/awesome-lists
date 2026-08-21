rule TrojanDownloader_Win64_Rhadamanthys_MK_2147976704_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Rhadamanthys.MK!MTB"
        threat_id = "2147976704"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "[BROWSER] Starting Browser Grabber" ascii //weight: 15
        $x_10_2 = "[SCAN] Master key found via heap scan" ascii //weight: 10
        $x_5_3 = "[ABE] Injecting into %S PID %lu..." ascii //weight: 5
        $x_3_4 = "[CDP] Launching Chrome with temp profile, port %d..." ascii //weight: 3
        $x_2_5 = "{\"id\":2,\"method\":\"Network.getAllCookies\"}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

