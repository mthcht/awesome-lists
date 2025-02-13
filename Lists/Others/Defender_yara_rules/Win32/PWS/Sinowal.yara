rule PWS_Win32_Sinowal_A_2147593219_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!A"
        threat_id = "2147593219"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$_2341234.TMP" ascii //weight: 1
        $x_1_2 = "_exp.exe" ascii //weight: 1
        $x_1_3 = "cgrb.exe" ascii //weight: 1
        $x_3_4 = "((l|L)(o|O)(g|G)(i|I)(n|N)|(u|U)(s|S)(e|E)(r|R)|(n|N)(a|A)(m|M)(e|E))[A-Za-z0-9_-]*=([A-Za-z0-9_-]+)" ascii //weight: 3
        $x_3_5 = "((p|P)(a|A)(s|S)(s|S)|(a|A)(u|U)(t|T)(h|H))[A-Za-z0-9_-]*=([A-Za-z0-9_-]+)" ascii //weight: 3
        $x_3_6 = "_i%s%05d.exe" ascii //weight: 3
        $x_3_7 = "i%s%05d.dll" ascii //weight: 3
        $x_3_8 = "i%s%05d.exe" ascii //weight: 3
        $x_1_9 = "Application: Internet Explorer" ascii //weight: 1
        $x_1_10 = "if (top.location != self.location) top.location = self.location;" ascii //weight: 1
        $x_1_11 = "document.login.PIN.value=\"*****\";" ascii //weight: 1
        $x_1_12 = "target=\"bbtgt\"" ascii //weight: 1
        $x_1_13 = "Content-Disposition: form-data; name=datafile; filename=\"%s\"" ascii //weight: 1
        $x_1_14 = "formObj.elements.getAttribute(temp1).value='';" ascii //weight: 1
        $x_1_15 = "\\hosts.sam" ascii //weight: 1
        $x_1_16 = "\\system32\\drivers\\etc\\hosts" ascii //weight: 1
        $x_3_17 = "_fuckAllProcesses@8" ascii //weight: 3
        $x_1_18 = "User-Agent: MSID [" ascii //weight: 1
        $x_1_19 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_20 = "\\..\\temp" ascii //weight: 1
        $x_1_21 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_3_22 = "ibm%05d.dll" ascii //weight: 3
        $x_3_23 = "ibm%05d.exe" ascii //weight: 3
        $x_2_24 = "/cib/login.jsp?*fiorg=" ascii //weight: 2
        $x_2_25 = "cib.ibanking-services.com" ascii //weight: 2
        $x_2_26 = "*vr-*ebanking.de" ascii //weight: 2
        $x_2_27 = "/ebanking*action=startlogin" ascii //weight: 2
        $x_2_28 = "/html/common/js/clientsniffer.js" ascii //weight: 2
        $x_2_29 = "/html/german/loginpin.jsp" ascii //weight: 2
        $x_3_30 = "\\_expiorer" ascii //weight: 3
        $x_2_31 = "banking.raiffeisen.at" ascii //weight: 2
        $x_2_32 = "/banking/loginpresentate.jsp" ascii //weight: 2
        $x_2_33 = "bankingportal.naspa.de" ascii //weight: 2
        $x_2_34 = "/config/check_domain.php" ascii //weight: 2
        $x_1_35 = "$_2341233.TMP" ascii //weight: 1
        $x_1_36 = "\\$a3e.tmp" ascii //weight: 1
        $x_1_37 = "Program Files\\Common Files\\Microsoft Shared\\Web Folders" ascii //weight: 1
        $x_2_38 = "/c/jsenc/main.js" ascii //weight: 2
        $x_3_39 = "_%s%05d.exe" ascii //weight: 3
        $x_2_40 = "ykb.teleweb.com.tr" ascii //weight: 2
        $x_2_41 = "_expIorer.exe" ascii //weight: 2
        $x_2_42 = "_expiorer" ascii //weight: 2
        $x_2_43 = "expIorer.dll" ascii //weight: 2
        $x_1_44 = "stsvcmem" ascii //weight: 1
        $x_1_45 = "stsvcmut" ascii //weight: 1
        $x_3_46 = "MSARCH_MUTEX_NAME" ascii //weight: 3
        $x_1_47 = "\\Microsoft Shared\\Web Folders" ascii //weight: 1
        $x_1_48 = "!<4(+6!6j!<!" ascii //weight: 1
        $x_2_49 = "7=70!)j-*-" ascii //weight: 2
        $x_1_50 = "!60-\"-'%0!7" ascii //weight: 1
        $x_3_51 = "!=D67%&%7!j ((D67%!*,j ((DD17!6wvj ((DD'6=401-j ((Dtuvwpqrs|}" ascii //weight: 3
        $x_2_52 = "7072')!)" ascii //weight: 2
        $x_2_53 = "7072')10" ascii //weight: 2
        $x_2_54 = "-74(%=d*%)!~dDD\"" ascii //weight: 2
        $x_2_55 = "771!6d*%)!~dDDN" ascii //weight: 2
        $x_3_56 = "/%06-*sj'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_57 = "2!6)=0sj'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_58 = "|qjvp}jvwj|v" ascii //weight: 3
        $x_3_59 = "&%*/-*#4+60%(j*%74%j !" ascii //weight: 3
        $x_3_60 = "&%*/-*#j6%-\"\"!-7!*j%0" ascii //weight: 3
        $x_3_61 = "'-&j-&%*/-*#i7!62-'!7j'+)" ascii //weight: 3
        $x_3_62 = "=/&j0!(!3!&j'+)j06" ascii //weight: 3
        $x_3_63 = "k!&%*/-*#n%'0-+*y70%60(+#-*" ascii //weight: 3
        $x_3_64 = "k&%*/-*#k(+#-*46!7!*0%0!j.74" ascii //weight: 3
        $x_3_65 = "k'-&k(+#-*j.74{n\"-+6#y" ascii //weight: 3
        $x_3_66 = "k,0)(k#!6)%*k(+#-*4-*j.74" ascii //weight: 3
        $x_3_67 = "k,0)(k'+))+*k.7k'(-!*07*-\"\"!6j.7" ascii //weight: 3
        $x_3_68 = "k'k.7!*'k)%-*j.7" ascii //weight: 3
        $x_3_69 = "n26in!&%*/-*#j !" ascii //weight: 3
        $x_2_70 = "!<4-+6!6" ascii //weight: 2
        $x_1_71 = "-!<4(+6!j!<!" ascii //weight: 1
        $x_1_72 = "-6!+<j!<!" ascii //weight: 1
        $x_1_73 = ")+>-((%j!<!" ascii //weight: 1
        $x_3_74 = ")=% -&sj'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_75 = " !2-(swj'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_76 = "#16/-|uj'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_77 = "(=%&6%|uj'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_78 = "3- #!pwj'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_79 = "4%()!6vsj'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_80 = "61)&%u}j'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_2_81 = "-74(%=d*%)!~dD" ascii //weight: 2
        $x_1_82 = "771!6dDDDD" ascii //weight: 1
        $x_3_83 = "0,!&-#'+1*0!6j'+)k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_84 = ")0&-*\"+j61k#%))%k<vqj4,4" ascii //weight: 3
        $x_3_85 = "17vvj61k#%))%k<vqj4,4" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_1_*))) or
            ((1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_2_*) and 8 of ($x_1_*))) or
            ((4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_2_*))) or
            ((1 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_B_2147593226_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!B"
        threat_id = "2147593226"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "id=%s&sv=%u&" ascii //weight: 5
        $x_2_2 = "&Unblock" ascii //weight: 2
        $x_2_3 = "Password2" ascii //weight: 2
        $x_1_4 = "Login:\"%s" ascii //weight: 1
        $x_1_5 = "%s(select):" ascii //weight: 1
        $x_1_6 = "#32770" ascii //weight: 1
        $x_1_7 = "&Remember this answer" ascii //weight: 1
        $x_1_8 = "PermissionDlg" ascii //weight: 1
        $x_1_9 = "$_2341233.TMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_F_2147602460_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!F"
        threat_id = "2147602460"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 ac 38 40 00 ff 25 78 11 40 00 [0-7] ff 25}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 00 01 ff 25 64 11 40 00 [0-7] ff 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_G_2147602461_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!G"
        threat_id = "2147602461"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 20 a0 40 00 ff 25 f4 10 40 00 [0-7] ff 25}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 15 14 a0 40 00 ff 25 f0 10 40 00 [0-7] ff 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_H_2147603685_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!H"
        threat_id = "2147603685"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 04 1b 40 00 ff 25 ?? ?? 40 00 [0-7] ff 25}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 15 14 a0 40 00 ff 25 ?? ?? 40 00 [0-7] ff 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_I_2147606177_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!I"
        threat_id = "2147606177"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 e7 be ad de ff 15 ?? ?? 40 00 85 c0 74 05}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 64 8b 1d 30 00 00 00 83 c3 06 8b 5b 06 8b 5b 0c 8b cb 39 43 18 7f 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_J_2147606893_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!J"
        threat_id = "2147606893"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 15 20 b0 40 00 90 ff 25 ?? ?? 40 00 [0-7] 90 ff 25}  //weight: 3, accuracy: Low
        $x_3_2 = {68 04 1b 40 00 90 ff 25 ?? ?? 40 00 [0-7] 90 ff 25}  //weight: 3, accuracy: Low
        $x_3_3 = {68 e7 be ad de}  //weight: 3, accuracy: High
        $x_2_4 = {81 45 08 88 6a 3f 24}  //weight: 2, accuracy: High
        $x_1_5 = {81 3c 11 50 45 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_K_2147608792_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!K"
        threat_id = "2147608792"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 20 00 41 00 9c 50 66 a1 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 18 10 40 00 9c 50 66 a1 ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_F_2147609723_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.F"
        threat_id = "2147609723"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 01 45 fc 8b 06 8b 7d f4 33 c7 [0-12] 83 f9 00 [0-6] 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 c4 83 c0 01 89 45 c4 [0-3] e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_L_2147609725_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!L"
        threat_id = "2147609725"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {9d 5d 9c 50 66}  //weight: 1, accuracy: High
        $x_1_2 = {66 a9 01 28 58 0f 85 ?? ?? ?? ?? 9d 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_M_2147610991_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!M"
        threat_id = "2147610991"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b e0 81 e5 00 f0 ff ff 89 6c 24 fc 89 54 24 f8 89 4c 24 f4 61 [0-2] 68 00 80 00 00 6a 00 ff 74 24 e4 ff 74 24 e4 8b 44 24 e4 ff e0}  //weight: 2, accuracy: Low
        $x_3_2 = {9c 50 66 a1 90 01 02 40 00 66 a9 90 01 02 58}  //weight: 3, accuracy: High
        $x_2_3 = {8b 45 c4 83 c0 01 89 45 c4 9c}  //weight: 2, accuracy: High
        $x_2_4 = {8b 45 f4 83 c0 01 89 45 f4 9c}  //weight: 2, accuracy: High
        $x_2_5 = {3d 0b 01 00 00 9c}  //weight: 2, accuracy: High
        $x_1_6 = {81 45 08 88 6a 3f 24}  //weight: 1, accuracy: High
        $x_1_7 = {81 3c 11 50 45 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_N_2147618838_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!N"
        threat_id = "2147618838"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff 83 2c 02 ad 75 07 32 c0 e9 04 00 81 bd}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 18 8d 85 ?? ?? ff ff 50 6a 00 6a 00 68 00 00 07 00 8b 4d 08 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {3d a0 68 06 00 73 0d 68 f4 01 00 00 ff 15 ?? ?? ?? ?? eb c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_O_2147619072_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!O"
        threat_id = "2147619072"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7d f4 03 75 2f 68}  //weight: 1, accuracy: High
        $x_1_2 = "{BEE686B9-4C84-4487-9D72-9F40F051E973}" ascii //weight: 1
        $x_1_3 = {2d 00 2d 00 63 00 70 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_P_2147627148_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!P"
        threat_id = "2147627148"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 65 1c 68 00 80 00 00 6a 00 ff 75 18 ff 75 e0 8b 45 10 ff e0}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 10 2b ca ff e0}  //weight: 2, accuracy: High
        $x_2_3 = {c7 45 f0 88 6a 3f 24}  //weight: 2, accuracy: High
        $x_1_4 = {03 d0 8b 4d 08 03 4d fc 88 11}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 64}  //weight: 1, accuracy: High
        $x_1_6 = {b8 00 00 00 00 05 ?? ?? ?? ?? (50|83 ec 04 89 ??)}  //weight: 1, accuracy: Low
        $x_1_7 = {0f b7 51 12 81 e2 00 20 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {b8 00 00 d9 6e 0d a1 eb 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {89 45 f0 b8 ?? ?? ?? ?? 05 ?? ?? ?? ?? 89 45 f4 0a 00 b8 ?? ?? ?? ?? 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_R_2147630475_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!R"
        threat_id = "2147630475"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 08 83 e8 04 50 8b 4d 10 51 8b 55 0c 52 8b 45 08 50 e8 ?? ?? ff ff 8b e5 5d c2 0c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 55 8b ec 83 ec ?? c7 45 fc ff ff ff ff c7 45 bc 00 00 00 00 eb 09 8b 45 bc 83 c0 01 89 45 bc 83 7d bc ?? 73 0e 90 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_S_2147630873_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!S"
        threat_id = "2147630873"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 5c 2e 5c 52 65 61 6c 48 61 72 64 44 69 73 6b 30 00 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64}  //weight: 1, accuracy: High
        $x_1_2 = "shutdown -r -f -t 0" ascii //weight: 1
        $x_1_3 = "%SystemRoot%\\System32\\Drivers\\*.sys" ascii //weight: 1
        $x_1_4 = {81 f9 55 aa 00 00 74 07}  //weight: 1, accuracy: High
        $x_1_5 = {3b f7 75 05 be 4f e6 40 bb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_T_2147630899_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!T"
        threat_id = "2147630899"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 80 a1 40 00 68 80 a1 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 bc 83 c0 01 89 45 bc 83 7d bc ?? 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c0 55 8b ec 83 ec 28 6a 20 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_U_2147631741_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!U"
        threat_id = "2147631741"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ff 83 ec 44 8b c1 c7 04 24 44 00 00 00 54 a1 ?? ?? ?? ?? ff d0 83 c4 44 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 6a ff 6a 00 6a ff ff 15 ?? ?? ?? ?? 68 00 01 00 00 ff 15 ?? ?? ?? ?? 83 c4 04 50 ff 15 ?? ?? ?? ?? 83 c4 04 6a 00 ff 15 ?? ?? ?? ?? 83 c4 04 6a 00 6a ff ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = {c7 45 e4 20 00 00 00 (eb|e9)}  //weight: 1, accuracy: Low
        $x_1_4 = {89 45 dc c7 45 d8 00 00 00 00 66 c7 05 ?? ?? ?? ?? 00 00 66 c7 45 fe 00 00 c7 45 d8 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_V_2147640923_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!V"
        threat_id = "2147640923"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 f8 8b 42 3c 8b 4d f8 0f b7 14 01 89 55 bc 8b 45 bc 25 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 ec 6b c0 28 8b 4d f0 8b 54 08 08 83 ea 01 52 8b 45 ec 6b c0 28 8b 4d 08 8b 11 8b 4d f0 03 54 08 0c 52}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 08 8b 42 10 ff d0 85 c0 75 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule PWS_Win32_Sinowal_W_2147643771_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!W"
        threat_id = "2147643771"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 75 f8 5a ff 72 3c 58 8b 4d f8 0f b7 14 01 89 55 bc 8b 45 bc 25 ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 ec 6b c0 28 8b 4d f0 8b 54 08 08 83 ea 02 52 ff 75 ec}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 08 8b 42 10 ff d0 85 c0 75}  //weight: 1, accuracy: High
        $x_1_4 = {3b f7 75 05 be 4f e6 40 bb}  //weight: 1, accuracy: High
        $x_1_5 = "NvCplDaemonTool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Sinowal_X_2147644691_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!X"
        threat_id = "2147644691"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 7d fc 1d (73 ??|0f 83 ?? ?? ?? ??) (8b 55 ??|ff 75 ??) c1 e2 04 (8b 45 ??|ff 75 ??) c1 e8 05}  //weight: 10, accuracy: Low
        $x_10_2 = {03 44 11 0c 50 e8}  //weight: 10, accuracy: High
        $x_10_3 = {42 65 65 70 02 00 81 (38|3a) ?? ?? ?? ?? (74|0f 84)}  //weight: 10, accuracy: Low
        $x_10_4 = {81 e2 00 ff 00 00 81 fa 00 45 00 00 75}  //weight: 10, accuracy: High
        $x_10_5 = {6a 08 68 aa 00 00 00 8d 45 f4 50 e8}  //weight: 10, accuracy: High
        $x_1_6 = {81 7d fc 01 17 00 00 73}  //weight: 1, accuracy: High
        $x_1_7 = {81 7d f8 89 2a 00 00 73}  //weight: 1, accuracy: High
        $x_1_8 = {81 7d fc c7 32 00 00 73}  //weight: 1, accuracy: High
        $x_1_9 = {81 7d fc 9b 63 00 00 73}  //weight: 1, accuracy: High
        $x_1_10 = {81 7d fc a1 75 00 00 73}  //weight: 1, accuracy: High
        $x_1_11 = {81 7d f4 a9 78 00 00 73}  //weight: 1, accuracy: High
        $x_1_12 = {81 7d f8 a9 78 00 00 73}  //weight: 1, accuracy: High
        $x_1_13 = {81 7d f4 69 a8 00 00 73}  //weight: 1, accuracy: High
        $x_1_14 = {81 7d f4 54 bc 00 00 (73|0f 83)}  //weight: 1, accuracy: Low
        $x_1_15 = {81 7d fc 54 bc 00 00 73}  //weight: 1, accuracy: High
        $x_1_16 = {81 7d fc 50 c3 00 00 73}  //weight: 1, accuracy: High
        $x_1_17 = {81 7d fc c1 c3 00 00 73}  //weight: 1, accuracy: High
        $x_1_18 = {81 7d f4 58 cc 00 00 (73|0f 83)}  //weight: 1, accuracy: Low
        $x_1_19 = {81 7d fc 58 cc 00 00 73}  //weight: 1, accuracy: High
        $x_1_20 = {81 7d fc 37 c7 00 00 73}  //weight: 1, accuracy: High
        $x_1_21 = {81 7d f4 49 d7 00 00 73}  //weight: 1, accuracy: High
        $x_1_22 = {81 7d fc 49 d7 00 00 73}  //weight: 1, accuracy: High
        $x_1_23 = {81 7d f4 0b fc 00 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 11 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_V_2147646764_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.V"
        threat_id = "2147646764"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AddPrintProvidorA" ascii //weight: 1
        $x_1_2 = {5c 5c 2e 5c 46 6c 74 4d 67 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 fc 8b 48 3c 89 4d f8 8b 55 fc 03 55 f8 0f b7 42 16 0d 00 20 00 00 8b 4d fc 03 4d f8 66 89 41 16 8b 55 ?? 52 8b 45 fc 50 8b 4d 08 51 e8 ?? ?? ?? ?? 83 c4 0c 89 45 f4 33 d2 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_Y_2147646766_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!Y"
        threat_id = "2147646766"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 04 4a 0f b6 4d 10 03 c1}  //weight: 1, accuracy: High
        $x_1_2 = {81 e1 00 f0 00 00 81 f9 00 40 00 00 (0f 85|75)}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b7 51 12 81 e2 00 20 00 00 (75|0f 85)}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 0c 03 (85 ?? ??|45 ??) 50 ff 55}  //weight: 1, accuracy: Low
        $x_2_5 = {3e 3e ff 75 0c 58 03 (85 ?? ??|45 ??) 50 ff 55}  //weight: 2, accuracy: Low
        $x_1_6 = {03 34 91 33 c6 40 00 c1 e0 04 [0-4] c1 e9 05 33 c1 [0-8] 83 e2 03}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 4d 0c 03 (8d ?? ??|4d ??) 51 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_Z_2147647781_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!Z"
        threat_id = "2147647781"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d f8 1d (73 ??|0f 83 ?? ?? ?? ??) [0-6] (8b 55 ??|ff 75 ??) c1 e2 04 (8b 45 ??|ff 75 ??) c1 e8 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 0c 03 4d ?? 51 ff 55 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_AA_2147649847_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!AA"
        threat_id = "2147649847"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 01 6a ff 68 00 08 00 00 68}  //weight: 5, accuracy: High
        $x_5_2 = {03 41 14 50 (ff 75|8b)}  //weight: 5, accuracy: Low
        $x_1_3 = {52 2b d2 42 0b d2 5a 75 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 2b ff 47 0b ff 5f 75 00}  //weight: 1, accuracy: High
        $x_1_5 = {51 2b c9 41 0b c9 59 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {8b 45 fc 83 c0 01 50 8f 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_AC_2147652612_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.AC"
        threat_id = "2147652612"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c 03 (8d ?? ??|4d ??) 51 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f4 33 d2 b9 ?? 00 00 00 f7 f1 89 45 f4 8b 55 0c 03 55 f4 8a 02 88 45 f3 [0-8] 8b 4d 08 03 4d f4 8a 55 f3 88 11 ff 75 fc 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Sinowal_AF_2147653338_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.AF"
        threat_id = "2147653338"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {35 13 89 00 00 d1 e0 3d 26 12 01 00 75}  //weight: 5, accuracy: High
        $x_1_2 = {00 70 64 62 2e 70 64 62 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6f 2e 70 64 62 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_AJ_2147653753_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.AJ"
        threat_id = "2147653753"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f af 4d b4 89 4d ac ff 75 ec 5a 3b 55 ac}  //weight: 1, accuracy: High
        $x_1_2 = {5a 66 89 0a 8b 45 b0 c1 e0 03 ff 75 a8 59}  //weight: 1, accuracy: High
        $x_1_3 = {8b 8d 78 ff ff ff d1 e1 2b c1 83 e8 02}  //weight: 1, accuracy: High
        $x_10_4 = "fdsksd.pdb" ascii //weight: 10
        $x_10_5 = {00 70 64 62 2e 70 64 62 00}  //weight: 10, accuracy: High
        $x_10_6 = "4fbdsv984o.pdb" ascii //weight: 10
        $x_10_7 = "msdtcdbgdbg.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Sinowal_AK_2147653871_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.AK"
        threat_id = "2147653871"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 74 08 6a 00 ff 15 ?? ?? ?? ?? 53 13 00 c1 f9 ?? 89 0d ?? ?? ?? ?? e8 ?? ?? 00 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 74 08 6a 00 ff 15 ?? ?? ?? ?? 53 14 00 c1 f9 ?? 51 8f 05 ?? ?? ?? ?? e8 ?? ?? 00 00 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {74 0c c7 05 ?? ?? ?? ?? 00 00 00 00 eb 0a c7 05 ?? ?? ?? ?? 01 00 00 00 eb ?? 5f 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {74 0a 6a 00 8f 05 ?? ?? ?? ?? eb 0a c7 05 ?? ?? ?? ?? 01 00 00 00 eb ?? 5f 5e 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_5 = "entweder oder entweder oder" ascii //weight: 1
        $x_1_6 = "dumbdumb.backpu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Sinowal_AB_2147679270_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!AB"
        threat_id = "2147679270"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 1c 0f 31 25 ff 00 00 00 83 e2 00 8b 4d 0c}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 b9 09 00 00 00 f7 f1 8b 54 95 ?? 52 68 04 01 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 10 85 c0 74 06}  //weight: 1, accuracy: Low
        $x_1_3 = {81 39 50 45 00 00 75 1a 8b 55 fc 0f b7 42 04 3d 64 86 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {0f b7 48 14 8d 54 0a 18 8b 45 fc 0f b7 48 06 6b c9 28 03 d1}  //weight: 1, accuracy: High
        $x_1_5 = {5b 81 eb 06 10 40 00 b8 26 10 40 00 03 c3 ff e0 06 00 90 e8 00 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = "/T /grant *S-1-1-0:F" ascii //weight: 1
        $x_1_7 = "&itag=ody&q=%s%%2C%02x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Sinowal_AE_2147718121_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sinowal.gen!AE"
        threat_id = "2147718121"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 81 57 e4 0a 03 00 44 44 44}  //weight: 1, accuracy: Low
        $x_1_2 = {81 57 e4 0a 44 44 44 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

