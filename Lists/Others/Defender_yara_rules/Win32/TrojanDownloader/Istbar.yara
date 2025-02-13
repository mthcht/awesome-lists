rule TrojanDownloader_Win32_Istbar_IV_2147803944_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Istbar.IV"
        threat_id = "2147803944"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff ff 83 c4 08 a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ff ff 83 c4 08 a3 ?? ?? ?? ?? 68 20 4e 00 00 ff 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 05}  //weight: 10, accuracy: Low
        $x_10_2 = "%s?version=%i&old_version=%s&istsvc=%i&istrecover=%i&sacc=%i&account_id=%i&soft=%s&rversion=%s&nr=%s&nd=%s&vinfo=%s" ascii //weight: 10
        $x_2_3 = "Software\\IST" ascii //weight: 2
        $x_2_4 = "istsvc.exe" ascii //weight: 2
        $x_2_5 = "Surf Accuracy" ascii //weight: 2
        $x_2_6 = "NeverISTsvc" ascii //weight: 2
        $x_1_7 = "%s&ac=%s&sac=%s" ascii //weight: 1
        $x_1_8 = "config_interval" ascii //weight: 1
        $x_1_9 = "subaccid" ascii //weight: 1
        $x_1_10 = "account_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Istbar_M_2147804021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Istbar.M"
        threat_id = "2147804021"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Istbar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateMutexA(i 0, i 0, t \"ysbMutex\")" ascii //weight: 1
        $x_1_2 = {77 77 77 2e 79 73 62 77 65 62 2e 63 6f 6d 2f 69 73 74 2f [0-21] 2f 69 73 74 64 6f 77 6e 6c 6f 61 64 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "Software\\IST" ascii //weight: 1
        $x_1_4 = "exe_start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

