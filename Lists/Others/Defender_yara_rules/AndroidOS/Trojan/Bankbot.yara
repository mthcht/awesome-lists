rule Trojan_AndroidOS_Bankbot_D_2147819336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Bankbot.D!MTB"
        threat_id = "2147819336"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Bankbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.sadasdwqewqas.dsqweqwds" ascii //weight: 1
        $x_1_2 = "uploadContacts.php" ascii //weight: 1
        $x_1_3 = "getInstalledApplications" ascii //weight: 1
        $x_1_4 = "starttracking" ascii //weight: 1
        $x_1_5 = "stopSelf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Bankbot_E_2147832193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Bankbot.E!MTB"
        threat_id = "2147832193"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Bankbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "service.webview.kiszweb" ascii //weight: 1
        $x_1_2 = "braziliankings.ddns" ascii //weight: 1
        $x_1_3 = "/mobileConfig.php" ascii //weight: 1
        $x_1_4 = "com.vtm.uninstall" ascii //weight: 1
        $x_1_5 = "startTracking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

