rule Trojan_Java_Octosca_PB_2147756678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/Octosca.PB!MTB"
        threat_id = "2147756678"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "Octosca"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Octopus Scanner - ver" ascii //weight: 1
        $x_1_2 = "Enumerating opened projects" ascii //weight: 1
        $x_1_3 = "newWatchService" ascii //weight: 1
        $x_1_4 = "octopus/Octopus" ascii //weight: 1
        $x_1_5 = "openProjectsURLs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

