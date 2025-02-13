rule TrojanDownloader_Win32_CoinMiner_I_2147688271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.I"
        threat_id = "2147688271"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\vrfBq" wide //weight: 1
        $x_1_2 = "kwws=22lqvlglrxvfrghu1frp2Uhydpshg2Ilohv2fj1h" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_J_2147716747_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.J!bit"
        threat_id = "2147716747"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://whatami.us.to/tc" ascii //weight: 1
        $x_1_2 = {6f 70 74 69 6f 6e 73 00 63 66 69 6c 65 00 63 63 61 72 67 73}  //weight: 1, accuracy: High
        $x_1_3 = {00 36 36 36 41 6e 6f 74 68 65 72 50 61 73 73 77 6f 72 64 36 36 36 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_K_2147716957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.K!bit"
        threat_id = "2147716957"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tracking.huijang.com/api.php" ascii //weight: 1
        $x_1_2 = {6e 76 73 72 76 63 33 32 2e 65 78 65 00 72 65 61 6c 73 63 68 65 64 2e 65 78 65 00 6a 75 73 63 68 65 64 2e 65 78 65 00 6d 63 73 68 69 65 6c 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {c7 04 24 00 00 00 00 e8 0a 46 02 00 89 04 24 e8 0a 46 02 00 e8 0d 46 02 00 b9 05 00 00 00 89 5c 24 ?? 8d 9d ?? ?? ?? ?? 89 1c 24 99 f7 f9 8b 04 95 ?? ?? ?? ?? 89 44 24 ?? ff 15 1c 54 43 00}  //weight: 1, accuracy: Low
        $x_1_4 = "%s://%s%s%s:%hu%s%s%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_L_2147718631_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.L!bit"
        threat_id = "2147718631"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 2f 2f 38 32 2e 31 34 36 2e 35 34 2e 31 38 37 2f [0-48] 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 6c 20 7a 65 63 2e [0-32] 20 2d 75 20 [0-32] 20 2d 70 20 78}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-48] 2e 6f 6e 69 6f 6e 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_QA_2147726089_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.QA!bit"
        threat_id = "2147726089"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "159.203.37.110/config/files/" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_QC_2147727334_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.QC!bit"
        threat_id = "2147727334"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$FILE = \"http://bytecoin.tk/m/svchosts.exe\"" wide //weight: 1
        $x_1_2 = "INETGET ( $FILE , @TEMPDIR & \"\\svchosts.exe\" )" wide //weight: 1
        $x_1_3 = "RUN ( \"svchosts.exe\" , @TEMPDIR )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_QD_2147727448_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.QD!bit"
        threat_id = "2147727448"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "attrib +s +h +r" ascii //weight: 1
        $x_1_2 = "net.exe stop" ascii //weight: 1
        $x_1_3 = "sc config WindowsUpdte type= own" ascii //weight: 1
        $x_1_4 = "http://zz.8282.space/nw/ss/" ascii //weight: 1
        $x_1_5 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 57 4f 57 36 34 [0-32] 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_QE_2147728645_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.QE!bit"
        threat_id = "2147728645"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "attrib +h" ascii //weight: 1
        $x_1_2 = "SCHTASKS /Create /SC MINUTE /MO" ascii //weight: 1
        $x_1_3 = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object System.Net.WebClient).DownloadFile" ascii //weight: 1
        $x_1_4 = {24 65 6e 76 3a 41 50 50 44 41 54 41 5c 75 70 64 61 74 65 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {34 2e 70 72 6f 67 72 61 6d 2d 69 71 2e 63 6f 6d 2f 75 70 6c 6f 61 64 73 2f [0-32] 2e 6a 70 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_QF_2147730054_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.QF!bit"
        threat_id = "2147730054"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 63 00 65 00 63 00 72 00 61 00 66 00 74 00 2e 00 73 00 69 00 74 00 65 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 73 00 2f 00 67 00 65 00 6f 00 69 00 70 00 2f 00 [0-48] 2e 00 73 00 71 00 6c 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 63 00 65 00 63 00 72 00 61 00 66 00 74 00 2e 00 73 00 69 00 74 00 65 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 73 00 2f 00 67 00 65 00 6f 00 69 00 70 00 2f 00 [0-48] 2e 00 64 00 62 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {52 00 55 00 4e 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_QG_2147730160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.QG!bit"
        threat_id = "2147730160"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 63 00 65 00 63 00 72 00 61 00 66 00 74 00 2e 00 73 00 69 00 74 00 65 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 73 00 2f 00 67 00 65 00 6f 00 69 00 70 00 2f 00 [0-48] 2e 00 73 00 71 00 6c 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {49 00 4e 00 45 00 54 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 63 00 6f 00 6d 00 66 00 6f 00 72 00 74 00 67 00 72 00 6f 00 75 00 70 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 [0-48] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {52 00 55 00 4e 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_M_2147730286_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.M"
        threat_id = "2147730286"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://185.219.223.119/stats/?arh=" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\WOW6432Node\\Shortcuter\\" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Shortcuter\\" ascii //weight: 1
        $x_1_4 = "SchTasks /Create /SC ONLOGON /TN \"" ascii //weight: 1
        $x_1_5 = "Set fRANDOM=CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_6 = "Set pRANDOM=CreateObject(\"WinHttp.WinHttpRequest.5.1\")" ascii //weight: 1
        $x_1_7 = {68 74 74 70 3a 2f 2f 05 00 2e 66 74 70 68 6f 73 74 69 6e 67 2e 70 77 2f 75 73 65 72 38 31 32 34 39 2f 34 39 31 38 2f 05 00 2e 74 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_Win32_CoinMiner_N_2147735571_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.N!bit"
        threat_id = "2147735571"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 74 74 70 3a 2f 2f 31 37 38 2e 31 35 39 2e 33 37 2e 31 31 33 2f [0-32] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_3_2 = {68 74 74 70 3a 2f 2f 31 39 34 2e 36 33 2e 31 34 33 2e 32 32 36 2f [0-32] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_3_3 = {68 74 74 70 3a 2f 2f 32 31 37 2e 31 34 37 2e 31 36 39 2e 31 37 39 2f [0-32] 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_2_4 = "electrum_data" wide //weight: 2
        $x_2_5 = "electrum_data\\wallets" ascii //weight: 2
        $x_2_6 = "recent_servers" wide //weight: 2
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_8 = ":::x123xsuccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_CoinMiner_AMK_2147788178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CoinMiner.AMK!MTB"
        threat_id = "2147788178"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "36"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ".boot" ascii //weight: 3
        $x_3_2 = "URLDownloadToFileW" ascii //weight: 3
        $x_3_3 = "BCryptDeriveKeyPBKDF2" ascii //weight: 3
        $x_3_4 = "WLSoftwareVersion" ascii //weight: 3
        $x_3_5 = "/showcode2" ascii //weight: 3
        $x_3_6 = "/logstatus" ascii //weight: 3
        $x_3_7 = "/bugcheck2" ascii //weight: 3
        $x_3_8 = "/skipactivexreg" ascii //weight: 3
        $x_3_9 = "Software\\WLkt" ascii //weight: 3
        $x_3_10 = "/bugcheckfull" ascii //weight: 3
        $x_3_11 = "/deactivate" ascii //weight: 3
        $x_3_12 = "Themida" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

