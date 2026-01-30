rule HackTool_Win32_TinyNetInfo_A_2147961994_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/TinyNetInfo.A"
        threat_id = "2147961994"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TinyNetInfo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6d5a95da-0ffe-4303-bb2c-39e182335a9f" ascii //weight: 1
        $x_1_2 = "U2VjdXJlUGFzc3dvcmQ=" wide //weight: 1
        $x_1_3 = "Cryption" ascii //weight: 1
        $x_1_4 = "GetDiskInformation" ascii //weight: 1
        $x_1_5 = "Information.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

