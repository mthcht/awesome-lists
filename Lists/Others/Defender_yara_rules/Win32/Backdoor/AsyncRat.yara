rule Backdoor_Win32_AsyncRat_HN_2147966669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/AsyncRat.HN!MTB"
        threat_id = "2147966669"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 30 43 0f b6 db 0f b6 04 1f 89 5c 24 ?? 00 c1 89 4c 24 ?? 0f b6 c9 8a 14 0f 88 14 1f 88 04 0f 02 04 1f 0f b6 c0 32 34 07 3b 74 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

