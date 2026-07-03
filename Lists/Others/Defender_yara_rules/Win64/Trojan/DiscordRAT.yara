rule Trojan_Win64_DiscordRAT_NA_2147972932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscordRAT.NA!MTB"
        threat_id = "2147972932"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 b9 e2 b9 d1 03 5e b2 60 5d 48 89 4c 24 60 48 b9 12 68 4f 49 df a9 9d cc 48 89 4c 24 68 48 8d 1d f9 65 0e 00 48 89 c1 bf 10 00 00 00 48 89 fe 4c 8d 44 24 70 49 89 f1 49 89 f2 48 8d 05 a4 0d 17 00 0f 1f 40 00 e8 7b 00 00 00 48 83 fb 30 75 13}  //weight: 2, accuracy: High
        $x_1_2 = "HKEY_CURRENT_CONFIGSetForegroundWindowgotestjsonbuildtextmultipar" ascii //weight: 1
        $x_1_3 = "BeaconIsAdminOpenClipboardExitWindowsEx" ascii //weight: 1
        $x_1_4 = "SuspendThreadStartServiceWSTART_PENDINGPAUSE_PENDING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DiscordRAT_NB_2147972933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscordRAT.NB!MTB"
        threat_id = "2147972933"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 48 14 83 f3 a5 88 58 12 0f b6 08 83 c1 78 88 08 0f b6 48 06 83 f1 32 88 48 06 0f b6 48 10 83 c1 82 88 48 10 0f b6 48 07 48 8b 94 24 90 00 00 00 31 ca 88 50 07}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 74 0c 40 0f b6 7c 0c 41 41 89 f8 31 f7 01 cf 48 83 fe 17 0f 83 58 03 00 00}  //weight: 2, accuracy: High
        $x_1_3 = "shutdownTimerremoteAddrStrhttp2dialCallpendingResetsclose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

