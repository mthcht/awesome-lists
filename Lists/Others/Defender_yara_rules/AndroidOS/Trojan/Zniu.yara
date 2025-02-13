rule Trojan_AndroidOS_Zniu_C_2147745475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Zniu.C!MTB"
        threat_id = "2147745475"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Zniu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Java_com_sdky_lyr_zniu_HuntReceive_nativeHandleReceive" ascii //weight: 2
        $x_2_2 = "Java_com_sdky_lyr_zniu_HuntUtils_nativePerpare" ascii //weight: 2
        $x_1_3 = "libhunt.so" ascii //weight: 1
        $x_1_4 = "%slocal.ziu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

