rule Trojan_AndroidOS_Gmuse_A_2147834891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Gmuse.A!MTB"
        threat_id = "2147834891"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Gmuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shengshitianai.com/update.txt" ascii //weight: 1
        $x_1_2 = "isupdate" ascii //weight: 1
        $x_1_3 = "/sdcard/.nofile/.android/.show" ascii //weight: 1
        $x_1_4 = "sdcard/lightbox.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

