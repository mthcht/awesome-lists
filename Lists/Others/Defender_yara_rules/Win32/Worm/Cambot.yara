rule Worm_Win32_Cambot_B_2147650463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cambot.B"
        threat_id = "2147650463"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cambot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bs_bot" ascii //weight: 1
        $x_1_2 = "tmrGrabber" ascii //weight: 1
        $x_1_3 = "/cmd.php?key=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Cambot_C_2147653360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cambot.C"
        threat_id = "2147653360"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cambot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\pspw.bss" wide //weight: 1
        $x_1_2 = "Select * from AntiVirusProduct" wide //weight: 1
        $x_1_3 = "xampp\\htdocs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

