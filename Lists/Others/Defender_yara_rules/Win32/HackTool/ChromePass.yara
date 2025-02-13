rule HackTool_Win32_ChromePass_2147692564_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ChromePass"
        threat_id = "2147692564"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ChromePass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChromePass" wide //weight: 1
        $x_1_2 = "/stext" wide //weight: 1
        $x_1_3 = "/skeepass" wide //weight: 1
        $x_1_4 = "origin_url, action_url, username_element, username_value, password_element, password_value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

