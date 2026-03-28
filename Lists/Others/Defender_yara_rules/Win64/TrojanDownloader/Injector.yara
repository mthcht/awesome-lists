rule TrojanDownloader_Win64_Injector_AMTB_2147965557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Injector!AMTB"
        threat_id = "2147965557"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownloadShellcodeAsync" ascii //weight: 1
        $x_1_2 = "ExecuteShellcode" ascii //weight: 1
        $x_1_3 = "ShellcodeDelegate" ascii //weight: 1
        $x_1_4 = "ShellcodeLoader" ascii //weight: 1
        $x_1_5 = "https://csrss.netlify.app/shellcode.bin" ascii //weight: 1
        $x_1_6 = "5ShellcodeLoader.Program+<DownloadShellcodeAsync>d__10" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

