rule Trojan_Linux_Slice_A_2147650009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Slice.gen!A"
        threat_id = "2147650009"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Slice"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "NOTICE %s :slice <destination> <lowport> <highport> <secs>" ascii //weight: 4
        $x_3_2 = "PRIVMSG %s :synflooding %s." ascii //weight: 3
        $x_3_3 = "ps aux | grep -E \"httpd|nginx|lsws|apache2\" | wc -l" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

