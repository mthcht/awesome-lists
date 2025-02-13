rule Trojan_Java_Octopus_A_2147760695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/Octopus.A!MTB"
        threat_id = "2147760695"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "Octopus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ecc.freeddns.org/ocs.txt" ascii //weight: 1
        $x_1_2 = "Cache134.dat" ascii //weight: 1
        $x_1_3 = "octopussetup.OctopusSetup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

