rule Trojan_MacOS_HzRat_A_2147919773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/HzRat.A!MTB"
        threat_id = "2147919773"
        type = "Trojan"
        platform = "MacOS: "
        family = "HzRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "trojan13download_file" ascii //weight: 1
        $x_1_2 = "trojan15execute_cmdline" ascii //weight: 1
        $x_1_3 = "trojan11send_cookie" ascii //weight: 1
        $x_1_4 = "trojan9XorMemoryEP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

