rule TrojanDownloader_Win32_Gdrexc_YA_2147734998_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gdrexc.YA!MTB"
        threat_id = "2147734998"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gdrexc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uc?export=download&id=" ascii //weight: 1
        $x_1_2 = "cmd.exe /c \"%appdata%" ascii //weight: 1
        $x_1_3 = "drive.google.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

