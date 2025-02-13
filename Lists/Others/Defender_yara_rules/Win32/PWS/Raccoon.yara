rule PWS_Win32_Raccoon_GG_2147773588_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Raccoon.GG!MTB"
        threat_id = "2147773588"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/stats/postback.php?trackid=" ascii //weight: 1
        $x_1_2 = "/stats/getstat.php?pub=" ascii //weight: 1
        $x_1_3 = "/dlc/partner.php?pub=" ascii //weight: 1
        $x_1_4 = "/download.php" ascii //weight: 1
        $x_1_5 = "&postback=" ascii //weight: 1
        $x_1_6 = "&user=" ascii //weight: 1
        $x_1_7 = "/do.php?pub=" ascii //weight: 1
        $x_1_8 = "/stats/itsru.php?pub=" ascii //weight: 1
        $x_1_9 = "KILLME" ascii //weight: 1
        $x_1_10 = "/c taskkill /im" ascii //weight: 1
        $x_1_11 = "/f & erase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

