rule Trojan_AndroidOS_Mobstspy_A_2147797800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Mobstspy.A"
        threat_id = "2147797800"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Mobstspy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/moc.ppatratsibom.www//:ptth" ascii //weight: 2
        $x_2_2 = "#WhatsApp//Media//WhatsApp Voice Notes##ACRCalls##CallRecorder##SMemo##DCIM#" ascii //weight: 2
        $x_2_3 = "/am.etuoredoc.www//:ptth" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

