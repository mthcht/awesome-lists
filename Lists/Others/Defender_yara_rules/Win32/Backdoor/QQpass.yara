rule Backdoor_Win32_QQpass_2147572244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/QQpass"
        threat_id = "2147572244"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "QQpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Start]" wide //weight: 1
        $x_1_2 = "[Url]" wide //weight: 1
        $x_1_3 = "[Kill]" wide //weight: 1
        $x_2_4 = "plmm|sex|beauty|free|My Pictures|girls|photos|" wide //weight: 2
        $x_1_5 = "2uZb\\1~-[t(~h*:5IU2.@#F,L~~|{~+)\\vem8PL+" wide //weight: 1
        $x_1_6 = "d_44154.nls" wide //weight: 1
        $x_1_7 = "M1b&R@FT3zzgnjp%?8jD" wide //weight: 1
        $x_1_8 = "WvZfLaF%E=mH~K+:2P84aAT" wide //weight: 1
        $x_1_9 = "KillMe.bat" wide //weight: 1
        $x_1_10 = "#32770" wide //weight: 1
        $x_1_11 = "TENCENT\\PLATFORM_TYPE_LIST\\" wide //weight: 1
        $x_1_12 = "wmimgrnt.exe" wide //weight: 1
        $x_1_13 = "c:\\QQMail.ini" wide //weight: 1
        $x_1_14 = "TopFox" ascii //weight: 1
        $x_1_15 = "HideFileExt" wide //weight: 1
        $x_1_16 = "regedit.notepad.taskmgr.ctfmon.userinit." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

