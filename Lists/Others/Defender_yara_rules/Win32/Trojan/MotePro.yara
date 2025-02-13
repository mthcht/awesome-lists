rule Trojan_Win32_MotePro_18066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MotePro"
        threat_id = "18066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MotePro"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "114"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 5c 5c 2e 5c 53 6d 61 72 74 76 73 64 00 00 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 00 25 30 32 58}  //weight: 3, accuracy: High
        $x_100_2 = {64 6f 77 6e 6c 6f 61 64 2f 70 72 6f 6d 6f 74 65 2f 70 72 6f 6d 6f 74 65 2e 64 6c 6c 00 5c 70 72 6f 6d 6f 74 65 2e 64 6c 6c 00 00 00 00 43 53 6b 79 70 65 49 6e 73 74 61 6c 6c 57 69 7a 61 72 64 00 43 54 72 61 79 49 63 6f 6e}  //weight: 100, accuracy: High
        $x_100_3 = {68 74 74 70 3a 2f 2f 73 74 61 74 69 73 74 69 63 73 2e 74 6f 6d 2e 63 6f 6d 2f 73 63 72 69 70 74 73 2f 53 6b 79 70 65 2f 73 6f 62 61 72 2e 65 78 65 00 00 00 68 74 74 70 3a 2f 2f 36 31 2e 31 33 35 2e 31 35 39 2e 31 38 33 2f 69 6e 73 74 61 6c 6c 65 72 2f 73 6f 62 61 72 2e 65 78 65 00 00 00 68 74 74 70 3a 2f 2f 73 6b 79 70 65 2e 74 6f 6d 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 69 6e 73 74 61 6c 6c 2f 73 6f 62 61 72 2e 65 78 65 00 5c 73 6f 62 61 72 2e 65 78 65}  //weight: 100, accuracy: High
        $x_3_4 = "&agentid=%s&op=%d&ver=%d&mac=%s" ascii //weight: 3
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
        $x_1_7 = "CreateMutexA" ascii //weight: 1
        $x_1_8 = "GetTempFileNameA" ascii //weight: 1
        $x_1_9 = "TrackPopupMenu" ascii //weight: 1
        $x_1_10 = "OpenClipboard" ascii //weight: 1
        $x_1_11 = "Shell_NotifyIconA" ascii //weight: 1
        $x_1_12 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MotePro_18066_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MotePro"
        threat_id = "18066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MotePro"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "103"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {50 72 6f 6d 6f 74 65 [0-4] 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 100, accuracy: Low
        $x_1_2 = "FxStatusEx_Launcher_Event" ascii //weight: 1
        $x_1_3 = "UrlMkGetSessionOption" ascii //weight: 1
        $x_1_4 = "Display Inline Videos" wide //weight: 1
        $x_1_5 = "Disable Script Debugger" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MotePro_18066_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MotePro"
        threat_id = "18066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MotePro"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://count.e-jok.cn/count.txt" ascii //weight: 3
        $x_1_2 = "SkypeClient.exe" ascii //weight: 1
        $x_3_3 = "http://www.e-jok.cn/count/updatedata.aspx?id=" ascii //weight: 3
        $x_3_4 = "http://www.e-jok.cn/cnfg/canview.txt" ascii //weight: 3
        $x_3_5 = "http://www.e-jok.cn/cnfg/_poplkh" ascii //weight: 3
        $x_2_6 = "<center><iframe width=%d height=%d frameborder=0 SCROLLING=no src=\"%s\"></iframe></center>" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MotePro_18066_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MotePro"
        threat_id = "18066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MotePro"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://statistics.tom.com/scripts/Skype/sobar.exe" ascii //weight: 3
        $x_3_2 = ".tom.com/download/promote/promote.dll" ascii //weight: 3
        $x_3_3 = ".e-jok.cn/count" ascii //weight: 3
        $x_2_4 = "/updatedata.aspx?id=" ascii //weight: 2
        $x_2_5 = "downnow.txt" ascii //weight: 2
        $x_1_6 = "<center><iframe width=%d height=%d frameborder=0 SCROLLING=no src=\"%s\"></iframe></center>" ascii //weight: 1
        $x_3_7 = "http://www.e-jok.cn/cnfg/" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MotePro_18066_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MotePro"
        threat_id = "18066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MotePro"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Victim_Mutex" ascii //weight: 1
        $x_2_2 = "&ver=%d&mac=%02X%02X%02X%02X%02X%02X" ascii //weight: 2
        $x_3_3 = "CLSID = s '{0FA24E3E-422C-4D94-A125-104F32352C90}'" ascii //weight: 3
        $x_2_4 = "http://www.myyiso.com/internet/" ascii //weight: 2
        $x_1_5 = "Software\\Microsoft\\Internet Explorer\\New Windows\\Allow" ascii //weight: 1
        $x_1_6 = "PromoteDemo Module" wide //weight: 1
        $x_2_7 = {46 78 53 74 61 74 75 73 45 78 5f 4c 61 75 6e 63 68 65 72 5f 45 76 65 6e 74 00 00 00 54 45 4d 50 5f 4c 4f 41 44 5f 4c 49 42 52 41 52 59 5f 55 53 45 49 4e 47 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_8 = {61 62 6f 75 74 3a 62 6c 61 6e 6b 00 00 00 00 42 75 74 74 6f 6e 50 6f 70 75 70 4b 69 6c 6c 65 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

