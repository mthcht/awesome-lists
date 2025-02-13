rule VirTool_Win64_Helcesz_A_2147890407_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Helcesz.A!MTB"
        threat_id = "2147890407"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Helcesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "telegram-bot-api.Chat" ascii //weight: 1
        $x_1_2 = ".RShell" ascii //weight: 1
        $x_1_3 = ".RegistryMethod" ascii //weight: 1
        $x_1_4 = "GeoIP" ascii //weight: 1
        $x_1_5 = "GetClipboard" ascii //weight: 1
        $x_1_6 = "CaptureScreen" ascii //weight: 1
        $x_1_7 = ".NewDocumentUpload" ascii //weight: 1
        $x_1_8 = ".Cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

