rule Backdoor_Win32_Zonebac_A_2147594494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zonebac.gen!A"
        threat_id = "2147594494"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonebac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://%s/%d/in/html%d.html?" ascii //weight: 2
        $x_2_2 = "id=%d&aid=%d&time=%s&fw=%d&v=%d&m=%d&vm=%d" ascii //weight: 2
        $x_2_3 = "http://%s/%d/checkin.php?" ascii //weight: 2
        $x_1_4 = "%s/drf%d.html" ascii //weight: 1
        $x_1_5 = {47 80 3f 00 75 fa 33 c0 ab ab 6a 00 ff 75 08 ab}  //weight: 1, accuracy: High
        $x_1_6 = {59 8b ca d3 e0 83 c2 06 09 45 fc 47 83 fa 24 7c e5}  //weight: 1, accuracy: High
        $x_1_7 = {8a 0c 01 3a 4c 24 04 74 08 40 83 f8 40 7c eb}  //weight: 1, accuracy: High
        $x_1_8 = {74 26 66 0f be 06 66 3b 45 0c 75 1c 0f bf 45 0c 50 ff 75 08}  //weight: 1, accuracy: High
        $x_1_9 = {8b 4d fc 03 c8 8d 46 01 99 f7 fb 8b 45 08 89 4d f8 33 c9 83 45 fc 04 8a 0c 02 0f be 04 06 c1 e0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zonebac_B_2147594495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zonebac.gen!B"
        threat_id = "2147594495"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonebac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\abc123.pid" ascii //weight: 2
        $x_1_2 = "209.167.111.110" ascii //weight: 1
        $x_1_3 = "222.133.3.210" ascii //weight: 1
        $x_1_4 = "216.95.196.22" ascii //weight: 1
        $x_1_5 = "iexplore.exe  http://" ascii //weight: 1
        $x_1_6 = "In InstallMyself (Moving File)n" ascii //weight: 1
        $x_1_7 = "Installing over:" ascii //weight: 1
        $x_1_8 = "update.exe UPDATE" ascii //weight: 1
        $x_1_9 = "iexplore.exe  %s/drf%d.html" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_11 = "Lexmark_X79-55" ascii //weight: 1
        $x_1_12 = "lsasss.exe" ascii //weight: 1
        $x_1_13 = "Process32First" ascii //weight: 1
        $x_1_14 = "Process32Next" ascii //weight: 1
        $x_1_15 = "RegOpenKeyExA" ascii //weight: 1
        $x_1_16 = "RegSetValueExA" ascii //weight: 1
        $x_1_17 = "FindNextFileA" ascii //weight: 1
        $x_1_18 = "FindFirstFileA" ascii //weight: 1
        $x_1_19 = "ad-watch.exe" ascii //weight: 1
        $x_1_20 = "isafe.exe" ascii //weight: 1
        $x_1_21 = "ca.exe" ascii //weight: 1
        $x_1_22 = "cavrid.exe" ascii //weight: 1
        $x_1_23 = "avp.exe" ascii //weight: 1
        $x_1_24 = "avciman.exe" ascii //weight: 1
        $x_1_25 = "avengine.exe" ascii //weight: 1
        $x_1_26 = "pavfnsvr.exe" ascii //weight: 1
        $x_1_27 = "pavsrv51.exe" ascii //weight: 1
        $x_1_28 = "pnmsrv.exe" ascii //weight: 1
        $x_1_29 = "pskmssvc.exe" ascii //weight: 1
        $x_1_30 = "srvload.exe" ascii //weight: 1
        $x_1_31 = "tpsrv.exe" ascii //weight: 1
        $x_1_32 = "webproxy.exe" ascii //weight: 1
        $x_1_33 = "vir.exe" ascii //weight: 1
        $x_1_34 = "swdoctor.exe" ascii //weight: 1
        $x_1_35 = "mxtask.exe" ascii //weight: 1
        $x_1_36 = "wmiprvse.exe" ascii //weight: 1
        $x_1_37 = "hsockpe.exe" ascii //weight: 1
        $x_1_38 = "vrfwsvc.exe" ascii //weight: 1
        $x_1_39 = "vrmonnt.exe" ascii //weight: 1
        $x_1_40 = "firewallntservice.exe" ascii //weight: 1
        $x_1_41 = "spysweeperui.exe" ascii //weight: 1
        $x_1_42 = "ssu.exe" ascii //weight: 1
        $x_1_43 = "wdfdataservice.exe" ascii //weight: 1
        $x_1_44 = "webrootdesktopfirewall.exe" ascii //weight: 1
        $x_1_45 = "vsmon.exe" ascii //weight: 1
        $x_1_46 = "zlclient.exe" ascii //weight: 1
        $x_1_47 = "mcagent.exe" ascii //weight: 1
        $x_1_48 = "mcdetect.exe" ascii //weight: 1
        $x_1_49 = "mcshield.exe" ascii //weight: 1
        $x_1_50 = "mctskshd.exe" ascii //weight: 1
        $x_1_51 = "mcvsescn.exe" ascii //weight: 1
        $x_1_52 = "mpfagent.exe" ascii //weight: 1
        $x_1_53 = "mscifapp.exe" ascii //weight: 1
        $x_1_54 = "mskagent.exe" ascii //weight: 1
        $x_1_55 = "oasclnt.exe" ascii //weight: 1
        $x_5_56 = ".php?STAGE=%d&CHECIN_ID=%d" ascii //weight: 5
        $x_1_57 = ": %2.2x %2.2xn" ascii //weight: 1
        $x_1_58 = "1604" ascii //weight: 1
        $x_1_59 = "1605" ascii //weight: 1
        $x_1_60 = "1606" ascii //weight: 1
        $x_1_61 = "1607" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((45 of ($x_1_*))) or
            ((1 of ($x_2_*) and 43 of ($x_1_*))) or
            ((1 of ($x_5_*) and 40 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 38 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zonebac_C_2147594496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zonebac.gen!C"
        threat_id = "2147594496"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonebac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {73 76 63 2e 65 78 65 00 6d 73 6d 70 73 76 63 2e 65 78 65 00 6d 70 65 6e}  //weight: 4, accuracy: High
        $x_4_2 = {61 76 70 2e 65 78 65 00 63 61 76 74 72 61 79 2e 65 78 65 00 63 61 76 72}  //weight: 4, accuracy: High
        $x_3_3 = "{FA531CC1-1497-11d3-A180-3333052276C3E}" ascii //weight: 3
        $x_3_4 = "update.php?" ascii //weight: 3
        $x_3_5 = "&FIREWALLS=%d" ascii //weight: 3
        $x_2_6 = {6a 14 99 59 f7 f9 83 c2 1e 69 d2 e8 03 00 00 52}  //weight: 2, accuracy: High
        $x_2_7 = {ff 74 24 04 6b c0 44 05}  //weight: 2, accuracy: High
        $x_1_8 = "AdjustTokenPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zonebac_F_2147601192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zonebac.gen!F"
        threat_id = "2147601192"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonebac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {e8 ef fb ff ff 68 00 00 08 00 ff 35 ?? ?? 41 00 e8 df fb ff ff 83 c4 28 5e}  //weight: 7, accuracy: Low
        $x_2_2 = {76 16 8b 15 ?? ?? ?? 00 8b c8 83 e1 1f 8a 0c 11 30 0c 38 40 3b c6 72 ea}  //weight: 2, accuracy: Low
        $x_2_3 = {ff 74 24 04 6b c0 44 05 ?? ?? ?? 00 50 ff 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 8b 4c 24 08 6b c0 44 ff 05 ?? ?? ?? 00 89 88 ?? ?? ?? 00 c3}  //weight: 2, accuracy: Low
        $x_2_4 = {ff 75 fc 6a 01 68 ff ?? 1f 00 ff 15 ?? ?? ?? 00 3b c6 74 08 56 50 ff 15 ?? ?? ?? 00 57 ff 15 ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_3_5 = {50 53 ff d6 81 7d f8 ?? ?? 00 00 74 3f 6a 02 57 6a f4 53 ff 15}  //weight: 3, accuracy: Low
        $x_3_6 = {ff d6 81 7d f0 67 2b 00 00 5e 75 1b}  //weight: 3, accuracy: High
        $x_1_7 = "http://88.80." ascii //weight: 1
        $x_1_8 = "\\abc123.pid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Zonebac_B_2147790463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zonebac.B"
        threat_id = "2147790463"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zonebac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\abc123.pid" ascii //weight: 1
        $x_1_2 = "209.167.111.110" ascii //weight: 1
        $x_1_3 = "222.133.3.210" ascii //weight: 1
        $x_1_4 = "216.95.196.22" ascii //weight: 1
        $x_1_5 = "iexplore.exe  http://%s/dc/%d/%d/%d/%d/%d/html%d.html" ascii //weight: 1
        $x_1_6 = "In InstallMyself (Moving File)n" ascii //weight: 1
        $x_1_7 = "Installing over:" ascii //weight: 1
        $x_1_8 = "update.exe UPDATE" ascii //weight: 1
        $x_1_9 = "iexplore.exe  %s/drf%d.html" ascii //weight: 1
        $x_1_10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_11 = "Lexmark_X79-55" ascii //weight: 1
        $x_1_12 = "lsasss.exe" ascii //weight: 1
        $x_1_13 = "Process32First" ascii //weight: 1
        $x_1_14 = "Process32Next" ascii //weight: 1
        $x_1_15 = "RegOpenKeyExA" ascii //weight: 1
        $x_1_16 = "RegSetValueExA" ascii //weight: 1
        $x_1_17 = "FindNextFileA" ascii //weight: 1
        $x_1_18 = "FindFirstFileA" ascii //weight: 1
        $x_1_19 = "ad-watch.exe" ascii //weight: 1
        $x_1_20 = "isafe.exe" ascii //weight: 1
        $x_1_21 = "ca.exe" ascii //weight: 1
        $x_1_22 = "cavrid.exe" ascii //weight: 1
        $x_1_23 = "avp.exe" ascii //weight: 1
        $x_1_24 = "avciman.exe" ascii //weight: 1
        $x_1_25 = "avengine.exe" ascii //weight: 1
        $x_1_26 = "pavfnsvr.exe" ascii //weight: 1
        $x_1_27 = "pavsrv51.exe" ascii //weight: 1
        $x_1_28 = "pnmsrv.exe" ascii //weight: 1
        $x_1_29 = "pskmssvc.exe" ascii //weight: 1
        $x_1_30 = "srvload.exe" ascii //weight: 1
        $x_1_31 = "tpsrv.exe" ascii //weight: 1
        $x_1_32 = "webproxy.exe" ascii //weight: 1
        $x_1_33 = "vir.exe" ascii //weight: 1
        $x_1_34 = "swdoctor.exe" ascii //weight: 1
        $x_1_35 = "mxtask.exe" ascii //weight: 1
        $x_1_36 = "wmiprvse.exe" ascii //weight: 1
        $x_1_37 = "hsockpe.exe" ascii //weight: 1
        $x_1_38 = "vrfwsvc.exe" ascii //weight: 1
        $x_1_39 = "vrmonnt.exe" ascii //weight: 1
        $x_1_40 = "firewallntservice.exe" ascii //weight: 1
        $x_1_41 = "spysweeperui.exe" ascii //weight: 1
        $x_1_42 = "ssu.exe" ascii //weight: 1
        $x_1_43 = "wdfdataservice.exe" ascii //weight: 1
        $x_1_44 = "webrootdesktopfirewall.exe" ascii //weight: 1
        $x_1_45 = "vsmon.exe" ascii //weight: 1
        $x_1_46 = "zlclient.exe" ascii //weight: 1
        $x_1_47 = "mcagent.exe" ascii //weight: 1
        $x_1_48 = "mcdetect.exe" ascii //weight: 1
        $x_1_49 = "mcshield.exe" ascii //weight: 1
        $x_1_50 = "mctskshd.exe" ascii //weight: 1
        $x_1_51 = "mcvsescn.exe" ascii //weight: 1
        $x_1_52 = "mpfagent.exe" ascii //weight: 1
        $x_1_53 = "mscifapp.exe" ascii //weight: 1
        $x_1_54 = "mskagent.exe" ascii //weight: 1
        $x_1_55 = "oasclnt.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (40 of ($x*))
}

