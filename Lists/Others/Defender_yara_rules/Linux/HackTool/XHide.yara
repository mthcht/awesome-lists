rule HackTool_Linux_Xhide_A_2147649978_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Xhide.gen!A"
        threat_id = "2147649978"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Xhide"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "XHide - Process Faker, by Schizoprenic Xnuxer Research (c) 2002" ascii //weight: 4
        $x_3_2 = "Example: %s -s \"klogd -m 0\" -d -p test.pid ./egg bot.conf" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

