rule TrojanClicker_Win32_VB_OO_2147598463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.OO"
        threat_id = "2147598463"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/adset.txt" ascii //weight: 1
        $x_1_2 = "/adlist.txt" ascii //weight: 1
        $x_1_3 = "/MMResult.asp" ascii //weight: 1
        $x_1_4 = "/adiepage.txt" ascii //weight: 1
        $x_1_5 = "/ieFavorites.txt" ascii //weight: 1
        $x_1_6 = "submit1=Submit&pcname=" ascii //weight: 1
        $x_1_7 = "del killme.bat" ascii //weight: 1
        $x_1_8 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 00 00 14 00 00 00 53 00 74 00 61 00 72 00 74 00 20 00 50 00 61 00 67 00 65 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_JO_2147598595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.JO"
        threat_id = "2147598595"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Micro\"&\"soft.XML\"&\"HTTP\")" wide //weight: 1
        $x_1_2 = "CreateObject(\"ADO\"&\"DB.Str\"&\"eam\")" wide //weight: 1
        $x_1_3 = "on error resume next:Set a = WScript.Arguments:if a.count=2 then Set x" wide //weight: 1
        $x_1_4 = "Open():s=x.responseBody:g.Write(s):g.SaveToFile a(1),2:g.close" wide //weight: 1
        $x_1_5 = "Open \"ge\"&\"t\",a(0),0:x.Send()" wide //weight: 1
        $x_1_6 = "\\winnt\\system32\\com" wide //weight: 1
        $x_1_7 = "\\windows\\system32\\com" wide //weight: 1
        $x_1_8 = "cmd.exe /c copy" wide //weight: 1
        $x_1_9 = "monver" wide //weight: 1
        $x_1_10 = "bakver" wide //weight: 1
        $x_1_11 = "regin.exe" wide //weight: 1
        $x_1_12 = "regsvr32 /s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_IG_2147602437_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.IG"
        threat_id = "2147602437"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 25 00 4a 00 43 00 4b 00 32 00 4c 00 5a 00 3a 00 51 00 42 00 47 00 2f 00 44 00 34 00 45 00 31 00 45 00 25 00 43 00 48 00 33 00 4e 00 36 00 4f 00 46 00 37 00 53 00 42 00 54 00 25 00 58 00 35 00 46 00 57 00 59 00 2e 00 50 00 2f 00 4d 00 43 00 35 00 41 00 32 00 55 00 39 00 56 00 37 00 46 00 38 00 41 00 43 00 52 00 31 00 39 00 46 00 51 00 25 00 37 00 32 00 2f 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 00 47 00 2f 00 44 00 34 00 45 00 31 00 45 00 25 00 43 00 48 00 33 00 4e 00 36 00 4f 00 46 00 37 00 53 00 42 00 54 00 25 00 58 00 35 00 46 00 57 00 59 00 2e 00 50 00 2f 00 4d 00 43 00 35 00 41 00 32 00 55 00 39 00 56 00 37 00 46 00 38 00 41 00 43 00 52 00 31 00 39 00 46 00 51 00 25 00 37 00 32 00 2f 00 4e 00 38 00 41 00 34 00 5a 00 38 00 41 00 25 00 51 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {38 00 41 00 44 00 49 00 31 00 25 00 4a 00 43 00 4b 00 32 00 4c 00 5a 00 3a 00 51 00 42 00 47 00 2f 00 44 00 34 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 4d 00 61 00 69 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 2e 00 56 00 42 00 50 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanClicker_Win32_VB_OS_2147606454_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.OS"
        threat_id = "2147606454"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://nexoa.com/rankboost.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_OT_2147606910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.OT"
        threat_id = "2147606910"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 00 00 18 00 00 00 63 00 74 00 66 00 6e 00 6f 00 6e 00 31 00 73 00 2e 00 65 00 78 00 65 00 00 00 00 00 24 00 00 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 73 00 74 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 38 00 00 00 49 00 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 00 65 00 72 00 6e 00 65 00 74 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 00 00 00 00 56 00 69 00 73 00 69 00 62 00 6c 00 65 00 00 00 26 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 33 00 36 00 30 00 74 00 6a 00 2e 00 63 00 6e 00 00 00 4e 00 61 00 76 00 69 00 67 00 61 00 74 00 65 00 00 00 00 00 2c 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 69 00 6e 00 66 00 6f 00 65 00 61 00 73 00 79 00 2e 00 63 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_GB_2147609693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.GB"
        threat_id = "2147609693"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 65 61 64 79 53 74 61 74 65 00 73 68 64 6f 63 76 77 2e 64 6c 6c 00 53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 00 57 65 62 42 72 6f 77 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = "http://www.google.com/search?hl=en&newwindow=1&q=" wide //weight: 1
        $x_1_3 = "http://search.yahoo.com/search?p=" wide //weight: 1
        $x_1_4 = "results_url_full_width_link" wide //weight: 1
        $x_1_5 = "/pagead/ads?client" wide //weight: 1
        $x_1_6 = "MyFireClick" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanClicker_Win32_VB_M_2147623721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.M"
        threat_id = "2147623721"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pk.xiaopohai.com" wide //weight: 1
        $x_1_2 = "User-Agent: ClickAdsByIE " wide //weight: 1
        $x_1_3 = "Accept: text/xml,application/xml," wide //weight: 1
        $x_1_4 = ":*:Enabled:SVCHOST.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_GE_2147626456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.GE"
        threat_id = "2147626456"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 4f 55 53 45 00 ?? ?? ?? ?? 74 68 65 70 75 62 6c 69 63 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = {77 69 6e 72 65 73 00 53 65 74 75 70 00 00 73 65 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 75 00 70 00 64 00 61 00 74 00 65 00 00 00 18 00 00 00 52 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_CU_2147638430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.CU"
        threat_id = "2147638430"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://tj.tongyicj.com:872/insert.asp" wide //weight: 1
        $x_1_2 = "backurl=http://a.oadz.com/link/C/" wide //weight: 1
        $x_1_3 = "C:\\WINDOWS\\svhost" wide //weight: 1
        $x_1_4 = "taskmgr.exe" wide //weight: 1
        $x_1_5 = "deleteurlcacheentry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanClicker_Win32_VB_JT_2147643126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.JT"
        threat_id = "2147643126"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://data1.yoou8.com/" wide //weight: 1
        $x_1_2 = {5c 00 41 00 44 00 3a 00 5c 00 77 00 6f 00 72 00 6b 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 5c 00 41 6d cf 91 0b 7a 8f 5e 32 00 5c 00 41 6d cf 91 0b 7a 8f 5e 5c 00 69 00 65 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: High
        $x_1_3 = "doubleclick" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_DF_2147647280_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.DF"
        threat_id = "2147647280"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "haojilm.com:81/" wide //weight: 1
        $x_1_2 = "DownfileRuny" ascii //weight: 1
        $x_1_3 = "Qixi2010Setup.exe" wide //weight: 1
        $x_1_4 = "referer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_DH_2147647907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.DH"
        threat_id = "2147647907"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Click\\Click.Dll" ascii //weight: 1
        $x_1_2 = "ClickModule" ascii //weight: 1
        $x_1_3 = "JinChengModule" ascii //weight: 1
        $x_1_4 = "BiaoTiModule" ascii //weight: 1
        $x_1_5 = "?comeID=" wide //weight: 1
        $x_1_6 = "tankreg.do?sid=" wide //weight: 1
        $x_1_7 = "Adodb.Stream" wide //weight: 1
        $x_1_8 = "Microsoft.XMLHTTP" wide //weight: 1
        $x_1_9 = "ReadyState" wide //weight: 1
        $x_1_10 = "responseBody" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_DI_2147648798_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.DI"
        threat_id = "2147648798"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "JiaMiSubText" ascii //weight: 4
        $x_2_2 = "DownDllTimer" ascii //weight: 2
        $x_1_3 = "winmgmts:{impersonationLevel=impersonate}" wide //weight: 1
        $x_1_4 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_DN_2147652979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.DN"
        threat_id = "2147652979"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dXNlcl9wcmVmKCJuZXR3b3JrLnByb3h5LnNvY2tzX3BvcnQiLCA4MCk" ascii //weight: 1
        $x_1_2 = "VGVycmE=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_DQ_2147654838_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.DQ"
        threat_id = "2147654838"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 68 ff 15 ?? ?? ?? ?? 8b d0 8d 4d ?? ff 15 ?? ?? ?? ?? 50 6a 74 ff 15 ?? ?? ?? ?? 8b d0 8d 4d ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0 8d 4d ?? ff 15 ?? ?? ?? ?? 50 6a 74 ff 15 ?? ?? ?? ?? 8b d0 8d 4d ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b d0}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 01 6a 68 8b 4d 08 8b 11 8b 45 08 50 ff 92 ?? ?? ?? ?? 50 8d 8d 4c ff ff ff 51 ff 15 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "http://adf.ly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_JF_2147695429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.JF"
        threat_id = "2147695429"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".com/ad/t5.asp" wide //weight: 1
        $x_1_2 = "1.vbp" wide //weight: 1
        $x_1_3 = "\\csh.dll" wide //weight: 1
        $x_1_4 = {53 65 74 42 72 6f 77 73 65 72 4d 75 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_ZI_2147717741_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.ZI!bit"
        threat_id = "2147717741"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 74 00 75 00 69 00 67 00 75 00 61 00 6e 00 67 00 2f 00 71 00 75 00 64 00 61 00 6f 00 [0-6] 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = "pos.baidu.com" wide //weight: 1
        $x_1_3 = {3c 00 61 00 20 00 69 00 64 00 3d 00 78 00 20 00 68 00 72 00 65 00 66 00 3d 00 2f 00 77 00 7a 00 73 00 2f 00 [0-16] 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 61 64 79 53 74 61 74 65 00 73 68 64 6f 63 76 77 2e 64 6c 6c 00 53 48 44 6f 63 56 77 43 74 6c 2e 57 65 62 42 72 6f 77 73 65 72 00 57 65 62 42 72 6f 77 73 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 [0-16] 70 00 72 00 6f 00 63 00 6d 00 67 00 72 00 65 00 78 00 [0-16] 70 00 72 00 6f 00 63 00 74 00 72 00 65 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {0b c0 74 02 ff e0 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ff d0 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_ZK_2147733006_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.ZK!bit"
        threat_id = "2147733006"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://vip9646.com" wide //weight: 1
        $x_1_2 = "cmd /c start iexplore.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_VB_EC_2147925139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/VB.EC!MTB"
        threat_id = "2147925139"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VB.Clipboard" ascii //weight: 1
        $x_1_2 = "/tuiguang/qudao" ascii //weight: 1
        $x_1_3 = "\\Snap.vbp" ascii //weight: 1
        $x_1_4 = "taskmgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

