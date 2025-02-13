rule BrowserModifier_Win32_VirtualMaid_15548_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/VirtualMaid"
        threat_id = "15548"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "VirtualMaid"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Virtual Maid  can't retrive infomation from" ascii //weight: 4
        $x_3_2 = "http://www.rsdn.ru/cgi-bin/search.exe?query=" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_VirtualMaid_15548_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/VirtualMaid"
        threat_id = "15548"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "VirtualMaid"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Virtual Maid" ascii //weight: 10
        $x_5_2 = "http://www.searchmaid.com/" ascii //weight: 5
        $x_5_3 = {4d 41 49 44 42 4d 50 32 00}  //weight: 5, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Internet Explorer\\SearchUrl" ascii //weight: 1
        $x_1_5 = "CloseAllRunIE End of Call" ascii //weight: 1
        $x_1_6 = {4d 41 49 44 44 4c 4c 00 56 69 72 74 75 61 6c 20 4d 61 69 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

