rule TrojanDropper_Win32_Startpage_DE_2147616894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Startpage.DE"
        threat_id = "2147616894"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a ff 6a 20 ff 15 ?? ?? 40 00 c7 ?? ?? 0b 00 00 00 6a 02 8d 55 dc 52 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 c7 ?? ?? 0c 00 00 00 6a 02 ff 15 ?? ?? 40 00 c7 ?? ?? 0d 00 00 00 6a 07 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 c7 ?? ?? 0e 00 00 00 c7 45 ?? ?? ?? 40 00 c7 ?? ?? 08 00 00 00 8d ?? ?? 8d ?? ?? ff 15 ?? ?? 40 00 6a 00 8d ?? ?? 50 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {40 00 52 00 45 00 47 00 20 00 41 00 44 00 44 00 20 00 48 00 4b 00 45 00 59 00 5f 00 4c 00 4f 00 43 00 41 00 4c 00 5f 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 20 00 2f 00 76 00 20 00 [0-32] 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 [0-32] 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = {61 00 74 00 74 00 72 00 69 00 62 00 20 00 2b 00 72 00 20 00 2b 00 73 00 20 00 2b 00 68 00 20 00 [0-32] 20 00 3e 00 6e 00 75 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "C:\\Program Files\\Internet Explorer\\iexplore.exe http://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Startpage_GG_2147631285_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Startpage.GG"
        threat_id = "2147631285"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "82"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Program Files\\procedure" ascii //weight: 10
        $x_10_2 = "\\nsRandom.dll" ascii //weight: 10
        $x_10_3 = "GetRandom" ascii //weight: 10
        $x_10_4 = "%%\\WMSysPr9.prx" ascii //weight: 10
        $x_10_5 = "Nlce.dll" ascii //weight: 10
        $x_10_6 = "winshutdown.vbs" ascii //weight: 10
        $x_10_7 = "\\OpenInternet.exe" ascii //weight: 10
        $x_10_8 = "#\\Mac\\MacJie.key" ascii //weight: 10
        $x_1_9 = "globe.png" ascii //weight: 1
        $x_1_10 = "hd.png" ascii //weight: 1
        $x_1_11 = "mail.png" ascii //weight: 1
        $x_1_12 = "music.png" ascii //weight: 1
        $x_1_13 = "my_computer.png" ascii //weight: 1
        $x_1_14 = "notepad.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Startpage_B_2147636923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Startpage.B"
        threat_id = "2147636923"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 ff 75 14 ff 75 10 8d 34 07 8a 04 07 50 e8 ?? ?? ?? ?? 83 c4 0c 47 3b 7d 0c 88 06 7c e0}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 66 06 00 00 39 45 10 be 88 08 00 00 75 17 50 ff 75 08 ff d7 6a 00 68 f4 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Startpage_AB_2147642514_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Startpage.AB"
        threat_id = "2147642514"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLSID\\{871C5380-42A0-1069-A2EA-08002B30309D}\\ShellFolder" ascii //weight: 1
        $x_1_2 = "WshShell.CreateShortcut(Favorites &" ascii //weight: 1
        $x_1_3 = "\\In\"&\"t\"&\"ern\"&\"et Expl\"&\"or\"&\"er\\M\"&\"a\"&\"i\"&\"n\\S\"&\"t\"&\"ar\"&\"t P\"&\"a\"&\"ge\"" ascii //weight: 1
        $x_1_4 = "\\Wi\"&\"nd\"&\"ows\\C\"&\"urren\"&\"tVers\"&\"ion\\R\"&\"u\"&\"n\\" ascii //weight: 1
        $x_1_5 = {2f 66 2f 71 2f 61 20 64 65 6c 20 22 fe 1a 1a 5c 49 6e 74 65 72 6e 65 74 2a 2e 2a 22}  //weight: 1, accuracy: High
        $x_1_6 = "1nkfile\\shellex\\IconHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDropper_Win32_Startpage_ZA_2147642530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Startpage.ZA"
        threat_id = "2147642530"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zhenlaji" wide //weight: 1
        $x_1_2 = "tongji.aectime.com/api/" wide //weight: 1
        $x_1_3 = "117.40.196.202/tj7/count.asp?mac=" wide //weight: 1
        $x_1_4 = "114search.118114.cn/search_web.html?" wide //weight: 1
        $x_1_5 = "dianxin.online.cq.cn/api/taobao/index.htm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Startpage_E_2147647011_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Startpage.E"
        threat_id = "2147647011"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Startpage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "ie=createobject(\"inte\"&\"rnetexplorer.app\"&\"licat\"&\"ion\")" ascii //weight: 4
        $x_4_2 = "ie.navigate \"h\"&\"tt\"&\"p://www.1\"&\"166f.co\"&\"m/?429" ascii //weight: 4
        $x_1_3 = "cmd.exe /c echo Y| cacls" ascii //weight: 1
        $x_1_4 = "lator\\Internat  Explorer" ascii //weight: 1
        $x_1_5 = "www.1166f.com/?pop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

