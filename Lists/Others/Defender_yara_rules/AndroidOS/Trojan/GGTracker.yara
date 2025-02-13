rule Trojan_AndroidOS_GGTracker_A_2147648486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GGTracker.A"
        threat_id = "2147648486"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GGTracker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 67 74 72 61 63 6b 2e 6f 72 67 2f 53 4d 31 ?? 3f 64 65 76 69 63 65 5f 69 64 3d}  //weight: 1, accuracy: Low
        $x_1_2 = "amaz0n-cloud.com/droid/droid.php" ascii //weight: 1
        $x_1_3 = "trackInstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

