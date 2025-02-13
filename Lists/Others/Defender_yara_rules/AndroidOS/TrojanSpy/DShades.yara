rule TrojanSpy_AndroidOS_DShades_A_2147753807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/DShades.A!MTB"
        threat_id = "2147753807"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "DShades"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Dark_Shades_Encrypted" ascii //weight: 2
        $x_1_2 = "ds_ucmd.php?imei=" ascii //weight: 1
        $x_1_3 = "post_gps.php" ascii //weight: 1
        $x_1_4 = "DARKROGUE" ascii //weight: 1
        $x_1_5 = "ds_emails.php" ascii //weight: 1
        $x_1_6 = "/system/bin/screencap -p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

