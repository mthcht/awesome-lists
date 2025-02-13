rule Trojan_AndroidOS_SideWinder_A_2147822341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SideWinder.A!MTB"
        threat_id = "2147822341"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SideWinder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p4d236d9a/pc31b3236/peae18bc4/p10cd395c" ascii //weight: 1
        $x_1_2 = "loadFromDisk" ascii //weight: 1
        $x_1_3 = "downloadedData" ascii //weight: 1
        $x_1_4 = "inMemoryFileLoadModule" ascii //weight: 1
        $x_1_5 = "Ldalvik/system/InMemoryDexClassLoader;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

