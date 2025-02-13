rule TrojanSpy_Win32_Reklode_A_2147688750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Reklode.A"
        threat_id = "2147688750"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Reklode"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Computer Name:" wide //weight: 1
        $x_1_2 = "syslgl.kg" wide //weight: 1
        $x_1_3 = "_#WMwareVirtualPrinter" wide //weight: 1
        $x_1_4 = "# Clerk 4.0.1U Log file" wide //weight: 1
        $x_1_5 = "User-Agent: Apple TV 5.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

