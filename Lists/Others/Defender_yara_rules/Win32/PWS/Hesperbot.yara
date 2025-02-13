rule PWS_Win32_Hesperbot_A_2147683068_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Hesperbot.A"
        threat_id = "2147683068"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesperbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c6 c1 e0 0b 33 c6 8b f3 8b df 8b f9 c1 ef 0b 33 f8 c1 ef 08 33 f8 89 4d ec 33 cf 89 5d e8 89 4d f8 83 fa 04}  //weight: 5, accuracy: High
        $x_5_2 = "core_x86.bin" ascii //weight: 5
        $x_5_3 = "_hesperus_core_entry" ascii //weight: 5
        $x_3_4 = "pt-botnet" wide //weight: 3
        $x_1_5 = "\\Microsoft\\Cryptography" ascii //weight: 1
        $x_1_6 = "\\Windows NT\\CurrentVersion" ascii //weight: 1
        $x_3_7 = "InstallDate" ascii //weight: 3
        $x_3_8 = "DigitalProductId" ascii //weight: 3
        $x_3_9 = "MachineGuid" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 4 of ($x_3_*))) or
            (all of ($x*))
        )
}

