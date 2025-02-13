rule Trojan_AndroidOS_Stampeg_A_2147654608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Stampeg.A"
        threat_id = "2147654608"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Stampeg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Moghava/kicker" ascii //weight: 1
        $x_1_2 = "sdcard/DCIM/Camera/" ascii //weight: 1
        $x_1_3 = "stamper.java" ascii //weight: 1
        $x_1_4 = "kicker.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

