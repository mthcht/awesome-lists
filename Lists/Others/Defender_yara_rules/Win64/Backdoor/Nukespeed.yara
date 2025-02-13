rule Backdoor_Win64_Nukespeed_SA_2147762594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Nukespeed.SA!MTB"
        threat_id = "2147762594"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Nukespeed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "movie64.dll" ascii //weight: 10
        $x_10_2 = "Cookie: _ga=%s%02d%d%d%02d%s; gid=%s%02d%d%03d%s" ascii //weight: 10
        $x_10_3 = "GA1.%d." ascii //weight: 10
        $x_10_4 = "WinHttpSendRequest" ascii //weight: 10
        $x_5_5 = "drukom" ascii //weight: 5
        $x_5_6 = "TransData" ascii //weight: 5
        $x_1_7 = "/total.php" ascii //weight: 1
        $x_1_8 = "/about.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

