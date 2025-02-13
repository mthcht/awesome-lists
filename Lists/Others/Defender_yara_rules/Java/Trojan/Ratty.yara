rule Trojan_Java_Ratty_A_2147755833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/Ratty.A!MTB"
        threat_id = "2147755833"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "Ratty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "de/sogomn/rat/gui/server/RattyGuiController" ascii //weight: 1
        $x_1_2 = "jre13v3bridge.jar" ascii //weight: 1
        $x_1_3 = "CurrentVersion\\Run /v \"Adobe Java bridge\" /d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Java_Ratty_B_2147760830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Java/Ratty.B!MTB"
        threat_id = "2147760830"
        type = "Trojan"
        platform = "Java: Java binaries (classes)"
        family = "Ratty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "de/sogomn/rat/RattyClient" ascii //weight: 1
        $x_1_2 = "keylogger" ascii //weight: 1
        $x_1_3 = "addToStartup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

