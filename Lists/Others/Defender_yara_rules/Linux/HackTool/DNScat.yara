rule HackTool_Linux_DNScat_A_2147818284_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/DNScat.A"
        threat_id = "2147818284"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "DNScat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "./dnscat --dns domain=skullseclabs.org,server=" ascii //weight: 5
        $x_2_2 = "encrypted session established! For added security, please verify" ascii //weight: 2
        $x_2_3 = "Starting: /bin/sh -c" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

