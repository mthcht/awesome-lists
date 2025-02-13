rule Worm_Win32_Codbot_2147706172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Codbot"
        threat_id = "2147706172"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Codbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GLOBAL CONST $DVD_FILE_ROOTPATH = \"autorun\\autorun." wide //weight: 1
        $x_1_2 = "GLOBAL CONST $DENY_PROCESS_LIST = STRINGSPLIT ( \"Burn|nero|clone|iso|dvd|cd|alc|bw|taskmgr\" , \"|\" )" wide //weight: 1
        $x_1_3 = "GLOBAL CONST $DENY_WINDOWS_LIST = STRINGSPLIT ( \"Ashampoo Burning Studio|Alcohol 120|Alcohol 52\" , \"|\" )" wide //weight: 1
        $x_1_4 = "REGWRITE ( \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" , \"NETLib\" , \"REG_SZ\" , @SCRIPTFULLPATH )" wide //weight: 1
        $x_1_5 = "#NoTrayIcon" wide //weight: 1
        $x_1_6 = "#RequireAdmin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

