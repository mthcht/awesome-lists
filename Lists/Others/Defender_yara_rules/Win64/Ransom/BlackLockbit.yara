rule Ransom_Win64_BlackLockbit_KK_2147968229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackLockbit.KK!MTB"
        threat_id = "2147968229"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackLockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\"wall_note\": \"shrt.readme." ascii //weight: 5
        $x_4_2 = "\"lock_ext\": \"shrt\"," ascii //weight: 4
        $x_3_3 = "All data encrypted" ascii //weight: 3
        $x_2_4 = "Software\\bgtextWallpaperWallpaper" ascii //weight: 2
        $x_1_5 = "delete_eventlogs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

