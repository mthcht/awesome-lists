rule Trojan_Java_Inqtana_B_2147746267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/Inqtana.B!MTB"
        threat_id = "2147746267"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "Inqtana"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Library/LaunchAgents/com.openbundle.plist" ascii //weight: 1
        $x_1_2 = "Library/LaunchAgents/com.pwned.plist" ascii //weight: 1
        $x_1_3 = "/w0rm-support.tgz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

