rule Misleading_MacOS_SpyMe_A_331383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:MacOS/SpyMe.A!xp"
        threat_id = "331383"
        type = "Misleading"
        platform = "MacOS: "
        family = "SpyMe"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.readpixel.spyme.daemon.install" ascii //weight: 1
        $x_1_2 = "/Library/PreferencesPanes/SpyMe" ascii //weight: 1
        $x_2_3 = "SpyMeToolSU" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

