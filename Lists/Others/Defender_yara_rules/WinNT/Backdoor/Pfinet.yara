rule Backdoor_WinNT_Pfinet_A_2147691974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Pfinet.A!dha"
        threat_id = "2147691974"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Pfinet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "write_peer_nfo=%c%d.%d.%d.%d:%d%c" ascii //weight: 1
        $x_1_2 = "wininet_activate" ascii //weight: 1
        $x_1_3 = "KeAddSystemServiceTable" ascii //weight: 1
        $x_1_4 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
        $x_2_5 = {73 65 72 76 69 63 65 73 2e 65 78 65 00 00 00 00 5c 3f 3f 5c 48 64 31 5c 6d 73 77 64 61 74 2e 64}  //weight: 2, accuracy: High
        $x_2_6 = "\\??\\Hd1\\msin" ascii //weight: 2
        $x_5_7 = {c7 45 e0 66 00 59 21 eb 2a a1 ?? ?? 01 00 89 45 d0 3b c3 75 e3 b8 01 00 00 c0 e9 ?? ?? ff ff 56 ff 75 10 8b 00 ff 34 88 e8 ?? ?? ff ff 89 45 e0 89 7e ?? 83 4d fc ff}  //weight: 5, accuracy: Low
        $x_5_8 = {46 66 83 fe 5a 76 9d 38 5d 0b 0f 84 ?? ?? 00 00 8b 45 fc 66 8b 48 30 66 81 f9 f2 01 0f 87 77 ?? ?? 00 8b 70 34 0f b7 c9 ff 75 0c 8b d1 c1 e9 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_WinNT_Pfinet_B_2147691975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Pfinet.B!dha"
        threat_id = "2147691975"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Pfinet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adobeupdater.exe" ascii //weight: 1
        $x_1_2 = "outlook.exe" ascii //weight: 1
        $x_1_3 = "msimn.exe" ascii //weight: 1
        $x_1_4 = "mozilla.exe" ascii //weight: 1
        $x_1_5 = "netscape.exe" ascii //weight: 1
        $x_1_6 = "opera.exe" ascii //weight: 1
        $x_1_7 = "firefox.exe" ascii //weight: 1
        $x_1_8 = "services.exe" ascii //weight: 1
        $x_1_9 = "CsrClientCallServer" ascii //weight: 1
        $x_1_10 = "KeAddSystemServiceTable" ascii //weight: 1
        $x_1_11 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
        $x_1_12 = "\\BaseNamedObjects\\{B93DFED5-9A3B-459b-A617-59FD9FAD693E}" wide //weight: 1
        $x_1_13 = "\\SystemRoot\\$NtUninstallQ722833$\\usbdev.sys" wide //weight: 1
        $x_1_14 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\usblink" wide //weight: 1
        $x_1_15 = "\\SystemRoot\\$NtUninstallQ722833$\\fixdata.dat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

