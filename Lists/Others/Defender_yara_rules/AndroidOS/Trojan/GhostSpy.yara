rule Trojan_AndroidOS_GhostSpy_U_2147923396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GhostSpy.U"
        threat_id = "2147923396"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GhostSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Device Connected111" ascii //weight: 2
        $x_2_2 = "SendOneGallery" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

