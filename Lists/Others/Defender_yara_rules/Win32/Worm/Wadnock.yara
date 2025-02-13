rule Worm_Win32_Wadnock_A_2147601587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wadnock.gen!A"
        threat_id = "2147601587"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wadnock"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {eb 20 6a 10 8d 44 24 04 50 6a 00 6a 64 8d 44 24 20 50 53 e8 ?? ?? ff ff 68 2c 01 00 00 e8 ?? ?? ff ff 80 3d ?? ?? ?? ?? 00 75 d7}  //weight: 6, accuracy: Low
        $x_6_2 = {74 26 83 fe 01 75 0f ba 75 08 00 00 8b 45 fc e8 ?? ?? ?? ?? eb 12 83 fe 02 75 0d ba 00 06 00 00 8b 45 fc e8}  //weight: 6, accuracy: Low
        $x_1_3 = "# System Hosts File" ascii //weight: 1
        $x_1_4 = "# DO NOT REMOVE IT !" ascii //weight: 1
        $x_1_5 = "!UDP.DDOS" ascii //weight: 1
        $x_1_6 = "!PROC.KILL" ascii //weight: 1
        $x_1_7 = "!ADD.DNSFAKE" ascii //weight: 1
        $x_1_8 = "!RUN" ascii //weight: 1
        $x_1_9 = "!URL.DOWNLOAD" ascii //weight: 1
        $x_1_10 = "!UPDATE" ascii //weight: 1
        $x_1_11 = "!AFTP.CONFIG" ascii //weight: 1
        $x_1_12 = "!URL.SPOOF" ascii //weight: 1
        $x_1_13 = "counter.php?action=knock" ascii //weight: 1
        $x_1_14 = "!proc.kill.* ftp.exe" ascii //weight: 1
        $x_1_15 = "!proc.kill.* tftp.exe" ascii //weight: 1
        $x_1_16 = "!proc.kill.* nh.exe" ascii //weight: 1
        $x_1_17 = "!proc.kill.* nethost.exe" ascii //weight: 1
        $x_1_18 = "!proc.kill.* syshost.exe" ascii //weight: 1
        $x_1_19 = "!proc.kill.* ppc.exe" ascii //weight: 1
        $x_1_20 = "!proc.kill.* paytime.exe" ascii //weight: 1
        $x_1_21 = "!proc.kill.* lp3mr1sh.exe" ascii //weight: 1
        $x_1_22 = "!proc.kill.* tibs.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

