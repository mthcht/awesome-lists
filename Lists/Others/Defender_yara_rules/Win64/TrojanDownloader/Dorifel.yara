rule TrojanDownloader_Win64_Dorifel_ARA_2147917676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Dorifel.ARA!MTB"
        threat_id = "2147917676"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 30 5e 80 70 01 5e 48 83 c0 02 48 39 ?? 75 f0}  //weight: 2, accuracy: Low
        $x_2_2 = {89 c2 41 80 34 16 5e 8d 50 01 44 39 fa 73 46}  //weight: 2, accuracy: High
        $x_2_3 = {80 30 6e 48 83 c0 01 48 39 d0 75 f4}  //weight: 2, accuracy: High
        $x_2_4 = {80 30 5e 48 83 c0 01 48 39 d0 75 f4}  //weight: 2, accuracy: High
        $x_2_5 = {83 f2 5e 88 10 83 85 18 02 00 00 01 8b 85 18 02 00 00 3b 85 dc 01 00 00 72 c3}  //weight: 2, accuracy: High
        $x_2_6 = {44 39 e0 73 09 80 34 07 6e 48 ff c0 eb f2}  //weight: 2, accuracy: High
        $x_1_7 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

