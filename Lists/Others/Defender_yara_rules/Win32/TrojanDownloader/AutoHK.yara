rule TrojanDownloader_Win32_AutoHK_A_2147717058_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AutoHK.A!bit"
        threat_id = "2147717058"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoHK"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WHR.Open(\"GET\", Url, True)" ascii //weight: 1
        $x_1_2 = "Base64dec(bBuf,bBuffer)" ascii //weight: 1
        $x_1_3 = "Base64dec(Mcode,s_ASM)" ascii //weight: 1
        $x_1_4 = "DllCall(wins, \"Ptr\", &Mcode, \"str\", TargetHost, \"Ptr\", &bBuf, \"Uint\", 0, \"Uint\", 0)" ascii //weight: 1
        $x_5_5 = "RegWrite, REG_SZ, HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce, upd, %A_Temp%\\%A_Scriptname%" ascii //weight: 5
        $x_5_6 = "FileCreateShortcut, \"%A_Temp%\\%A_ScriptName%\", %A_Startup%\\Golupdate.lnk,,,,1" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_AutoHK_C_2147730508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AutoHK.C"
        threat_id = "2147730508"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoHK"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "UrlDownloadToFile, https://upload.cat" ascii //weight: 4
        $x_2_2 = "Frombase64String('T'+'V'+'q'+'Q'+'A'+'A'+'M'" ascii //weight: 2
        $x_1_3 = "RunWait powershell -noexit -windowstyle hidden  %PWScript% ,, hide" ascii //weight: 1
        $x_1_4 = "RunWait %Appdata%\\Microsoft" ascii //weight: 1
        $x_1_5 = "https://pastebin.com/raw/Vr83T9s5" ascii //weight: 1
        $x_1_6 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_7 = "\\Windows\\window2.vbs\" /F,, hide" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_AutoHK_D_2147730519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AutoHK.D"
        threat_id = "2147730519"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoHK"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://pastebin.com/raw/hR1iwmqb" ascii //weight: 2
        $x_1_2 = "RunWait powershell -noexit -windowstyle hidden" ascii //weight: 1
        $x_2_3 = "https://wiknet.wikaba.com" wide //weight: 2
        $x_2_4 = "https://checktest.www1.biz" wide //weight: 2
        $x_1_5 = "/FeedBack.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

