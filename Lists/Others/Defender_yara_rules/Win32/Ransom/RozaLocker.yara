rule Ransom_Win32_RozaLocker_MKV_2147951457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RozaLocker.MKV!MTB"
        threat_id = "2147951457"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RozaLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 53 83 ec 04 8b 5c 24 10 8b 74 24 14 0f b6 43 1d 89 04 24 e8 ?? ?? ?? ?? 32 06 30 03 0f b6 43 1e 89 04 24 e8}  //weight: 5, accuracy: Low
        $x_3_2 = "Roza-Locker" ascii //weight: 3
        $x_2_3 = ".rmlock" ascii //weight: 2
        $x_1_4 = "ReadMe.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

