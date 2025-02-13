rule TrojanSpy_Win32_Savnut_A_2147646222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Savnut.A!dll"
        threat_id = "2147646222"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Savnut"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LCLICKNDBL" wide //weight: 1
        $x_1_2 = "showpopup" wide //weight: 1
        $x_1_3 = "%010d.vkey.jpg" wide //weight: 1
        $x_1_4 = "tvbotoff" wide //weight: 1
        $x_1_5 = "VkeyGrabberW" ascii //weight: 1
        $x_1_6 = "WestpackOnClickW" ascii //weight: 1
        $x_3_7 = {8b 4d cc 8b 55 f0 56 89 71 08 8b 42 f4 68 ?? ?? ?? 10 03 c0 50 52 ff 31 ff 15}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

