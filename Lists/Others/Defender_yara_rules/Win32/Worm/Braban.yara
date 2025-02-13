rule Worm_Win32_Braban_B_2147583556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Braban.B"
        threat_id = "2147583556"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Braban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 ff 30 64 89 20 8b 45 fc e8 ?? ?? ?? ?? 8b f0 85 f6 7e 2c bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 81 ea 06 12 0f 00 e8 ?? ?? ?? ?? 8b 55 f4 8d 45 f8 e8 ?? ?? ?? ?? 43 4e 75 d9 8b c7 8b 55 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Braban_G_2147601380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Braban.G"
        threat_id = "2147601380"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Braban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\windows\\system32\\OSSMTP.dll" ascii //weight: 10
        $x_10_2 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_3 = "\\atapi16.sys" wide //weight: 10
        $x_10_4 = "\\privada" wide //weight: 10
        $x_10_5 = "msmsgs" ascii //weight: 10
        $x_1_6 = "addZIP_IncludeFilesNewer" ascii //weight: 1
        $x_1_7 = "addZIP_IncludeFilesOlder" ascii //weight: 1
        $x_2_8 = "AZIP32.DLL" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

