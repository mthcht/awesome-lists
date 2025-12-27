rule HackTool_Win32_CardTool_AMTB_2147955995_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CardTool!AMTB"
        threat_id = "2147955995"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CardTool"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Card Type C with backdoor detected" ascii //weight: 1
        $x_1_2 = "Failed to read card information!" ascii //weight: 1
        $x_1_3 = "Card Type A detected" ascii //weight: 1
        $x_1_4 = "Insert card or press any key to exit" ascii //weight: 1
        $x_1_5 = "Failed to list card readers" ascii //weight: 1
        $x_1_6 = "Card Serial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

