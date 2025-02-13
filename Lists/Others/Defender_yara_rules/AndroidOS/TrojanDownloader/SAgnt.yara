rule TrojanDownloader_AndroidOS_SAgnt_B_2147827624_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/SAgnt.B!MTB"
        threat_id = "2147827624"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cl_appupdate" ascii //weight: 1
        $x_1_2 = "/AppUpdateExample.txt" ascii //weight: 1
        $x_1_3 = "_update_updatecomplete" ascii //weight: 1
        $x_1_4 = "install_non_market_apps" ascii //weight: 1
        $x_1_5 = "_snewverapk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_AndroidOS_SAgnt_B_2147827624_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/SAgnt.B!MTB"
        threat_id = "2147827624"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 02 0b 00 38 02 ?? 00 22 04 ?? 00 70 10 ?? ?? 04 00 13 02 00 02 71 30 ?? ?? 0b 02 0c 02 5b 42 13 00 d0 00 00 02 d8 00 00 04 61 06 0f 00 71 20 ?? ?? 0b 00 0a 02 81 28 bd 86 5a 46 14 00 d8 00 00 04 61 06 0f 00 71 20 ?? ?? 0b 00 0a 02 81 28 bd 86 5a 46 15 00 d8 00 00 04 54 42 13 00 1a 05 ?? 00 6e 20 ?? ?? 52 00 0a 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_AndroidOS_SAgnt_C_2147832325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:AndroidOS/SAgnt.C!MTB"
        threat_id = "2147832325"
        type = "TrojanDownloader"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HokoSDK" ascii //weight: 1
        $x_1_2 = "com/mobile/indiapp/b" ascii //weight: 1
        $x_1_3 = "/track.mtracking.mobi/package" ascii //weight: 1
        $x_1_4 = "com/bbm/download" ascii //weight: 1
        $x_1_5 = "copyToSDCard" ascii //weight: 1
        $x_1_6 = "cpid.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

