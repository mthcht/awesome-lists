rule Ransom_AndroidOS_Koler_A_2147811435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Koler.A!xp"
        threat_id = "2147811435"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Koler"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://hotgraderpornprivate.eu" ascii //weight: 1
        $x_1_2 = "FBI_Anti-Piracy_Warning" ascii //weight: 1
        $x_1_3 = "your Device has been locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

