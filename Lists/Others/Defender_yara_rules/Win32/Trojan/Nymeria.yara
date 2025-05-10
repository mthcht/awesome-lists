rule Trojan_Win32_Nymeria_SN_2147775589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymeria.SN!MTB"
        threat_id = "2147775589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://ip-score.com/checkip/" wide //weight: 1
        $x_1_2 = "/c Pl2.exe -f" wide //weight: 1
        $x_1_3 = "WScript.Sleep 5000" wide //weight: 1
        $x_1_4 = "\\Mozilla\\Firefox\\Profiles\\" wide //weight: 1
        $x_1_5 = "\\key3.db" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymeria_RPH_2147838786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymeria.RPH!MTB"
        threat_id = "2147838786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$_LL11L1LL11 = GUICTRLCREATEMONTHCAL" wide //weight: 1
        $x_1_2 = "$_11LLLL11LL = MOUSEGETCURSOR" wide //weight: 1
        $x_1_3 = "$_11L1111L11LL = CONSOLEWRITEERROR" wide //weight: 1
        $x_1_4 = "$_11L1LLLLLLL1 = UDPRECV" wide //weight: 1
        $x_1_5 = "$_111L11LL111 = @WINDOWSDIR" wide //weight: 1
        $x_1_6 = "$_L11LLL1L11 = GUICTRLSETDATA" wide //weight: 1
        $x_1_7 = "$_1LLLLLLL111 = UDPSTARTUP" wide //weight: 1
        $x_1_8 = "$_L1LLLLL1LLL = FILEEXISTS" wide //weight: 1
        $x_1_9 = "$_111LLLL11 = WINEXISTS" wide //weight: 1
        $x_1_10 = "$_1L1L1LLLL1L = BINARYMID" wide //weight: 1
        $x_1_11 = "$_11LLLL1LL11 = WINWAIT" wide //weight: 1
        $x_1_12 = "$_11L11LLLLLL = @USERNAME" wide //weight: 1
        $x_1_13 = "$_11LL11LLLL1 = @OSVERSION" wide //weight: 1
        $x_1_14 = "$_L11L1LLL1LL = SHUTDOWN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymeria_RPG_2147840898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymeria.RPG!MTB"
        threat_id = "2147840898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$_LL1111LLL1L = WINLIST" wide //weight: 1
        $x_1_2 = "$_LL1LLLLL1L11 = SQRT" wide //weight: 1
        $x_1_3 = "$_L1LL111LL11 = VARGETTYPE" wide //weight: 1
        $x_1_4 = "$_L11LLLLL1L1 = TCPACCEPT" wide //weight: 1
        $x_1_5 = "$_1111LL1LL1L = MOUSEGETPOS" wide //weight: 1
        $x_1_6 = "$_LL1L1LLLL1L = UDPCLOSESOCKET" wide //weight: 1
        $x_1_7 = "$_11L1L1L1 = CONTROLENABLE" wide //weight: 1
        $x_1_8 = "$_11111111 = CHR" wide //weight: 1
        $x_1_9 = "$_11L1LLLLL = ISARRAY" wide //weight: 1
        $x_1_10 = "$_1LL1LLLLL = SHELLEXECUTEWAIT" wide //weight: 1
        $x_1_11 = "$_11LL1LL111 = ABS" wide //weight: 1
        $x_1_12 = "$_1LLL1L1111 = GUICTRLSENDMSG" wide //weight: 1
        $x_1_13 = "$_11L11LL = GUISETSTYLE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymeria_RPO_2147841060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymeria.RPO!MTB"
        threat_id = "2147841060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CONSOLESTATE /Hide" ascii //weight: 1
        $x_1_2 = "echo GET FUCKED NIGGE" ascii //weight: 1
        $x_1_3 = "start ping 208.67.222.222 -t -l 65500" ascii //weight: 1
        $x_1_4 = "taskkill /F /IM taskmgr.exe" ascii //weight: 1
        $x_1_5 = "goto die" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymeria_ARA_2147897509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymeria.ARA!MTB"
        threat_id = "2147897509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "qjwrkrdct.pdf" ascii //weight: 2
        $x_2_2 = "qlinhm.xl" ascii //weight: 2
        $x_2_3 = "TempMode" ascii //weight: 2
        $x_2_4 = "silent=1tE25GA2C3Onwk21" ascii //weight: 2
        $x_2_5 = "Setup=ijh-d.vbe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymeria_GPB_2147911777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymeria.GPB!MTB"
        threat_id = "2147911777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CHR ( 80 ) & CHR ( 75 ) & CHR ( 5 ) & CHR ( 6" ascii //weight: 1
        $x_1_2 = "ELSEIF PROCESSEXISTS (" ascii //weight: 1
        $x_1_3 = "IF FILEEXISTS ( @TEMPDIR & \"/passlist.txt" ascii //weight: 1
        $x_1_4 = "REGDELETE ( \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" , \"Microsoft Update" ascii //weight: 1
        $x_1_5 = "IF FILEEXISTS ( @APPDATADIR & \"\\Mozilla\\Firefox\\Profiles" ascii //weight: 1
        $x_1_6 = "logins.json" ascii //weight: 1
        $x_1_7 = "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_8 = "FILEDELETE ( @USERPROFILEDIR & \"\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" ascii //weight: 1
        $x_1_9 = "FILEDELETE ( @APPDATADIR & \"\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 1
        $x_1_10 = "IF DLLSTRUCTGETDATA ( $TKEYHOOKS" ascii //weight: 1
        $x_1_11 = "FileZilla Password" ascii //weight: 1
        $x_1_12 = "Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_13 = "SELECT * FROM logins" ascii //weight: 1
        $x_1_14 = "Opera Software\\Opera Stable\\Login Data" ascii //weight: 1
        $x_1_15 = "CryptStringToBinaryA" ascii //weight: 1
        $x_1_16 = "PK11SDR_Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nymeria_NMA_2147936977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymeria.NMA!MTB"
        threat_id = "2147936977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 00 46 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 46 00 54 00 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 3d 00 20 00 22 00 30 00 78 00 22 00 20 00 54 00 48 00 45 00 4e 00 20 00 52 00 45 00 54 00 55 00 52 00 4e 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 20 00 28 00 20 00 24 00 [0-47] 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {49 46 20 53 54 52 49 4e 47 4c 45 46 54 20 28 20 24 [0-47] 20 2c 20 32 20 29 20 3d 20 22 30 78 22 20 54 48 45 4e 20 52 45 54 55 52 4e 20 42 49 4e 41 52 59 20 28 20 24 [0-47] 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {49 00 46 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 49 00 53 00 58 00 44 00 49 00 47 00 49 00 54 00 20 00 28 00 20 00 24 00 [0-47] 20 00 29 00 20 00 54 00 48 00 45 00 4e 00 20 00 52 00 45 00 54 00 55 00 52 00 4e 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 20 00 28 00 20 00 22 00 30 00 78 00 22 00 20 00 26 00 20 00 24 00 [0-47] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {49 46 20 53 54 52 49 4e 47 49 53 58 44 49 47 49 54 20 28 20 24 [0-47] 20 29 20 54 48 45 4e 20 52 45 54 55 52 4e 20 42 49 4e 41 52 59 20 28 20 22 30 78 22 20 26 20 24 [0-47] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {49 00 46 00 20 00 4e 00 4f 00 54 00 20 00 24 00 [0-47] 20 00 28 00 20 00 24 00 [0-47] 20 00 28 00 20 00 24 00 [0-47] 20 00 29 00 20 00 26 00 20 00 24 00 [0-47] 20 00 29 00 20 00 41 00 4e 00 44 00 20 00 4e 00 4f 00 54 00}  //weight: 1, accuracy: Low
        $x_1_6 = {49 46 20 4e 4f 54 20 24 [0-47] 20 28 20 24 [0-47] 20 28 20 24 [0-47] 20 29 20 26 20 24 [0-47] 20 29 20 41 4e 44 20 4e 4f 54}  //weight: 1, accuracy: Low
        $x_1_7 = "= EXECUTE ( BINARYTOSTRING ( \"0x5837324851373251463043313228245837324851373251363931382C202458373248513732513639383429\" )" ascii //weight: 1
        $x_1_8 = "AwAAAAQoAAAAAAAAAAABAAjuGW/74nfYaea+3PoomH/10Zt32/Ox0jPpahf3y4Skg0ueqEhI0w8/LW0A" ascii //weight: 1
        $x_1_9 = "HYIT_Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nymeria_NAZ_2147941069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nymeria.NAZ!MTB"
        threat_id = "2147941069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nymeria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "&= DLLSTRUCTGETDATA" ascii //weight: 2
        $x_1_2 = "EXECUTE ( \"1\" )" ascii //weight: 1
        $x_1_3 = {3d 00 20 00 40 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-47] 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 40 55 53 45 52 50 52 4f 46 49 4c 45 44 49 52 20 26 20 22 5c [0-47] 22}  //weight: 1, accuracy: Low
        $x_1_5 = "( \"wscript.exe\" , \"djoin\" , \"+\" , FALSE )" ascii //weight: 1
        $x_1_6 = "RUN ( @PROGRAMFILESDIR & \"\\Internet Explorer\\iexplore.exe \" & $STEMP )" ascii //weight: 1
        $x_1_7 = "$RESULT &= CHRW ( $XOR )" ascii //weight: 1
        $x_1_8 = {26 00 3d 00 20 00 43 00 48 00 52 00 57 00 20 00 28 00 20 00 24 00 [0-47] 20 00 5b 00 20 00 24 00 [0-47] 20 00 5d 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_9 = {26 3d 20 43 48 52 57 20 28 20 24 [0-47] 20 5b 20 24 [0-47] 20 5d 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

