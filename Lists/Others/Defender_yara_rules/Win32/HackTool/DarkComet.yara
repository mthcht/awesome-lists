rule HackTool_Win32_DarkComet_2147689268_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DarkComet"
        threat_id = "2147689268"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkComet"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 61 72 6b 43 6f 6d 65 74 ?? 52 41 54 20 2d 20 4e 65 77 20 55 73 65 72 20 21}  //weight: 1, accuracy: Low
        $x_1_2 = "-DarkComet-RAT Web Site and Software Agreement" ascii //weight: 1
        $x_1_3 = "DarkComet is synchronized with no-ip dns service" ascii //weight: 1
        $x_1_4 = "AActive darkcomet skin form system" ascii //weight: 1
        $x_1_5 = "DarkComet Remote Administration Tool" wide //weight: 1
        $x_1_6 = "DarkComet aka Unremote NAT aka SynRAT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

