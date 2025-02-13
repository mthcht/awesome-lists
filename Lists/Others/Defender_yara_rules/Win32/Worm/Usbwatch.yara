rule Worm_Win32_Usbwatch_A_2147602339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Usbwatch.A"
        threat_id = "2147602339"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Usbwatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "360"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "USBWATCHPRO" ascii //weight: 100
        $x_100_2 = "USBWATCHPRO" wide //weight: 100
        $x_100_3 = "%s\\AutoRun.inf" ascii //weight: 100
        $x_10_4 = "\\SERVICES.EXE" ascii //weight: 10
        $x_10_5 = "%SystemDrive%\\Recycled\\" ascii //weight: 10
        $x_10_6 = "ShowSuperHidden" ascii //weight: 10
        $x_10_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii //weight: 10
        $x_30_8 = {83 f8 02 59 89 45 f4 0f 8c f7 02 00 00 8d 85 ?? ?? ff ff c7 45 ?? 01 00 00 00 50 8d 85 ?? ?? ff ff 68 ?? ?? 40 00 50 ff d3 83 c4 0c 8d 85 ?? ?? ff ff 57 50 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 8d 85 ?? ?? ff ff 6a 00 50 ff 15 ?? ?? 40 00 8d 85 d4 f6 ff ff 50 8d 85 ?? ?? ff ff 68 ?? ?? 40 00 50 ff d3 8b 1d ?? ?? 40 00 83 c4 0c 8d 85 ?? ?? ff ff 68 80 00 00 00 50 ff d3 8d 85 ?? ?? ff ff 6a 00 50 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? 40 00 85 c0}  //weight: 30, accuracy: Low
        $x_30_9 = {68 00 01 00 00 51 ff 15 ?? ?? 40 00 bf ?? ?? 40 00 83 c9 ff 33 c0 8d 94 24 ?? ?? 00 00 f2 ae f7 d1 2b f9 8b f7 8b d9 8b fa 83 c9 ff f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 84 24 ?? ?? 00 00 83 e1 03 50 f3 a4 8d [0-6] 51 e8 ?? ?? ff ff 83 c4 08 8d [0-6] 6a 00 52 ff 15}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_30_*) and 3 of ($x_10_*))) or
            ((3 of ($x_100_*) and 2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Usbwatch_B_2147615812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Usbwatch.B"
        threat_id = "2147615812"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Usbwatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "USBWATCHPRO" ascii //weight: 10
        $x_10_2 = "%s\\AutoRun.inf" ascii //weight: 10
        $x_10_3 = "%SystemDrive%\\RECYCLE" ascii //weight: 10
        $x_1_4 = "NoDriveTypeAutoRun" ascii //weight: 1
        $x_1_5 = "ShowSuperHidden" ascii //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii //weight: 1
        $x_1_7 = "645FF040-5081-101B-9F08-00AA002F954E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

