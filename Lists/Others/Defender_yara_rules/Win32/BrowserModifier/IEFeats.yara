rule BrowserModifier_Win32_IEFeats_14938_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/IEFeats"
        threat_id = "14938"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "IEFeats"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 1
        $x_1_2 = "Start Page" ascii //weight: 1
        $x_1_3 = "Default_Page_URL" ascii //weight: 1
        $x_1_4 = "Use Search Asst" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_3_6 = "AtlAxWinFeatModified" ascii //weight: 3
        $x_2_7 = "http://looking-for.cc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_IEFeats_14938_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/IEFeats"
        threat_id = "14938"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "IEFeats"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 74 74 70 3a 2f 2f 61 64 (30|2d|39) (30|2d|39) 2e 63 6f 6d 2f 61 64 2e 70 68 70}  //weight: 10, accuracy: Low
        $x_10_2 = "http://winshow.biz/feat/" ascii //weight: 10
        $x_1_3 = "{587DBF2D-9145-4c9e-92C2-1F953DA73773}" ascii //weight: 1
        $x_1_4 = "go-advertising.com" wide //weight: 1
        $x_1_5 = {5b 66 6f 72 62 69 64 64 65 6e 5d 00 5b 6b 65 79 77 6f 72 64 73 5d}  //weight: 1, accuracy: High
        $x_1_6 = "iefeatsl.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_IEFeats_14938_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/IEFeats"
        threat_id = "14938"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "IEFeats"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "{587DBF2D-9145-4c9e-92C2-1F953DA73773}" ascii //weight: 10
        $x_10_2 = "Software\\Microsoft\\Internet Explorer\\Main" ascii //weight: 10
        $x_10_3 = "Start Page" ascii //weight: 10
        $x_5_4 = "Default_Page_URL" ascii //weight: 5
        $x_5_5 = "Use Search Asst" ascii //weight: 5
        $x_1_6 = "http://lookfor.cc?pin=%05d" ascii //weight: 1
        $x_1_7 = "http://lookfor.cc/sp.php?pin=%05d" ascii //weight: 1
        $x_1_8 = "http://iefeadsl.com/feat/" ascii //weight: 1
        $x_5_9 = "InternetOpenUrlA" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

