rule TrojanDownloader_MacOS_Shlayer_A_2147829963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Shlayer.A"
        threat_id = "2147829963"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Shlayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "/Users/admin/work/fca7b6ba6b868838" ascii //weight: 3
        $x_1_2 = "https://e.%@" ascii //weight: 1
        $x_1_3 = "sleep %lu; open \"%@\"" ascii //weight: 1
        $x_2_4 = {2f 74 6d 70 2f 09 00 06 00 5f 69 6e 73 74 61 6c 6c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MacOS_Shlayer_B_2147830589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Shlayer.B"
        threat_id = "2147830589"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Shlayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f1 7a 88 4c 07 1b 50 58 50 58 90 50 58 48 ff c8 48 83 f8 fc 75}  //weight: 1, accuracy: High
        $x_1_2 = {a1 33 10 d2 57 00 b1 33 20 00 00 d1 33 23 e5 59 00 f4 33 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MacOS_Shlayer_E_2147848943_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MacOS/Shlayer.E!MTB"
        threat_id = "2147848943"
        type = "TrojanDownloader"
        platform = "MacOS: "
        family = "Shlayer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "org.w0lf.cDockHelper" ascii //weight: 1
        $x_1_2 = "import com.apple.dock /tmp/dock.plist" ascii //weight: 1
        $x_1_3 = "/tmp/dminst" ascii //weight: 1
        $x_1_4 = "sleep %lu; open \"%@\"" ascii //weight: 1
        $x_1_5 = "com.dock2master.Dock2MasterHelper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

